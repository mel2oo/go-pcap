package mempool

import (
	"errors"
	"io"

	"github.com/mel2oo/go-pcap/memview"
)

// Controls whether representation invariants are checked in buffer.repOk. When
// enabled, a panic occurs when an invariant is found to be violated.
var CheckInvariants = false

// A variable-sized buffer whose backing storage is drawn from a fixed-sized
// pool. Clients must return the backing storage to the pool by calling Release.
//
// Based on bytes.Buffer.
type Buffer interface {
	// Returns a MemView of length Len() that holds the unread portion of the
	// buffer. The MemView is valid for use only until the next buffer
	// modification (that is, only until the next call to a method like Read,
	// Write, Reset, or Truncate). The MemView aliases the buffer content at least
	// until the next buffer modification, so changes to the MemView will affect
	// the result of future reads.
	Bytes() memview.MemView

	// Returns the number of bytes of the unread portion of the buffer; Len() ==
	// Bytes().Len().
	Len() int

	// Empties the buffer. An alias for Release.
	Reset()

	// Empties the buffer and returns its underlying storage to the pool.
	Release()

	// Write(p) appends the contents of the slice p to the buffer, obtaining
	// additional storage from the pool as needed.
	//
	// Returns the number of bytes written from p and EmptyPool if the write
	// stopped early.
	io.Writer

	// ReadFrom(r) copies the contents of the io.Reader r into the buffer until
	// EOF or an error is encountered. Additional storage is obtained from the
	// pool as needed.
	//
	// Returns the number of bytes copied. Any error except EOF encountered during
	// the read is also returned.
	//
	// EmptyPool is returned if additional storage is needed, but the buffer pool
	// is empty. It is possible for this to happen even when all of r is copied:
	// if the end of r coincides exactly with the end of the buffer's allocated
	// storage, and r doesn't immediately report its EOF, ReadFrom will try to
	// obtain additional storage from the pool before reading the EOF from r.
	io.ReaderFrom
}

var ErrEmptyPool = errors.New("mempool.Buffer: pool is empty")
var errNegativeRead = errors.New("mempool.Buffer: reader returned negative count from Read")

type buffer struct {
	pool bufferPool

	// Contents of the buffer start at chunks[0][readOffset] (inclusive) and end
	// at chunks[len(chunks)-1][writeOffset] (exclusive).
	//
	// Invariants, checked by repOk:
	//   - this is empty when the buffer is empty.
	//   - all elements have length and capacity pool.chunkSize_bytes.
	chunks [][]byte

	// Contents of the buffer start at chunks[0][readOffset] (inclusive). This is
	// where to start reading from.
	//
	// Invariants, checked by repOk:
	//   - readOffset == 0 when len(chunks) == 0.
	//   - readOffset < pool.chunkSize_bytes when len(chunks) > 0.
	//   - readOffset < writeOffset when len(chunks) == 1.
	//
	// XXX Currently not meaningfully used, since we read via Bytes(). This is
	// here in case we want to implement io.Reader in the future.
	readOffset int

	// Contents of the buffer end at chunks[len(chunks)-1][writeOffset]
	// (exclusive). This is where to start writing to.
	//
	// Invariants, checked by repOk:
	//   - writeOffset > 0 when len(chunks) > 0.
	//   - readOffset < writeOffset when len(chunks) == 1.
	writeOffset int
}

func newBuffer(pool bufferPool) Buffer {
	return &buffer{
		pool: pool,
	}
}

var _ Buffer = (*buffer)(nil)

// Checks representation invariants. Panics if any invariant is broken.
func (buf *buffer) repOk() {
	if !CheckInvariants {
		return
	}

	assert := func(b bool) {
		if !b {
			panic("broken invariant")
		}
	}

	// Invariants on chunks. See documentation on chunks.
	//
	// We don't check that `chunks` is empty when the buffer is empty, since we
	// don't have any other way of seeing whether the buffer is empty.
	for _, chunk := range buf.chunks {
		assert(len(chunk) == buf.pool.chunkSize_bytes)
		assert(cap(chunk) == buf.pool.chunkSize_bytes)
	}

	// Invariants on readOffset. See documentation on readOffset.
	if len(buf.chunks) == 0 {
		assert(buf.readOffset == 0)
	}
	if len(buf.chunks) > 0 {
		assert(buf.readOffset < buf.pool.chunkSize_bytes)
	}
	if len(buf.chunks) == 1 {
		assert(buf.readOffset < buf.writeOffset)
	}

	// Invariants on writeOffset. See documentation on writeOffset.
	if len(buf.chunks) > 0 {
		assert(buf.writeOffset > 0)
	}
	if len(buf.chunks) == 1 {
		assert(buf.readOffset < buf.writeOffset)
	}
}

func (buf *buffer) Bytes() memview.MemView {
	result := memview.MemView{}
	for idx, chunk := range buf.chunks {
		if len(buf.chunks) == 1 {
			result.Append(memview.New(chunk[buf.readOffset:buf.writeOffset]))
		} else if idx == 0 {
			result.Append(memview.New(chunk[buf.readOffset:]))
		} else if idx == len(buf.chunks)-1 {
			result.Append(memview.New(chunk[:buf.writeOffset]))
		} else {
			result.Append(memview.New(chunk))
		}
	}
	return result
}

func (buf *buffer) Len() int {
	numChunks := len(buf.chunks)
	if numChunks == 0 {
		return 0
	}

	bytesAllocated := buf.pool.chunkSize_bytes * numChunks
	bytesAlreadyRead := buf.readOffset
	bytesNotYetWritten := buf.pool.chunkSize_bytes - buf.writeOffset
	return bytesAllocated - bytesAlreadyRead - bytesNotYetWritten
}

func (buf *buffer) Reset() { buf.Release() }

func (buf *buffer) Release() {
	if buf == nil {
		return
	}

	// Check representation invariants for the buffer's chunks.
	buf.repOk()

	buf.pool.release(buf.chunks)
	buf.chunks = nil
	buf.readOffset = 0

	// Check representation invariants for the resulting buffer.
	buf.repOk()
}

// Grows the buffer to provide space for up to n more bytes. Returns the chunk
// index and offset where bytes should be written, and the amount of space
// available in the buffer for writing. If n is non-positive or the resulting
// amount of space available is 0, then no change is made to the buffer, and the
// chunk index and offset returned are meaningless.
//
// This method leaves the buffer in an inconsistent state. The caller is
// responsible for re-establishing the buffer's invariants.
func (buf *buffer) grow(n int) (chunkIdx, offset, availableBytes int) {
	// Determine result values for the buffer's current state.
	{
		chunkIdx = 0
		offset = 0
		availableBytes = 0

		if len(buf.chunks) > 0 {
			chunkIdx = len(buf.chunks) - 1
			offset = buf.writeOffset
			availableBytes = buf.pool.chunkSize_bytes - buf.writeOffset
		}
	}

	spaceNeeded := n - availableBytes
	if spaceNeeded <= 0 {
		// No need to allocate more space.
		return chunkIdx, offset, availableBytes
	}

	// Get more space from the pool.
	chunksNeeded := (spaceNeeded + buf.pool.chunkSize_bytes - 1) / buf.pool.chunkSize_bytes
	chunksObtained := 0
	for ; chunksObtained < chunksNeeded; chunksObtained++ {
		chunk := buf.pool.getChunk()
		if chunk == nil {
			// Pool is empty.
			break
		}
		buf.chunks = append(buf.chunks, chunk)
	}

	if offset == buf.pool.chunkSize_bytes {
		chunkIdx++
		offset = 0
	}
	availableBytes += chunksObtained * buf.pool.chunkSize_bytes
	return chunkIdx, offset, availableBytes
}

func (buf *buffer) Write(p []byte) (n int, err error) {
	defer buf.repOk()

	if len(p) == 0 {
		return 0, nil
	}

	// Make as much space as we can for p.
	chunkIdx, offset, bytesAvail := buf.grow(len(p))
	if bytesAvail < len(p) {
		err = ErrEmptyPool
	}

	// Per grow(), chunkIdx and offset are meaningless when bytesAvail is 0.
	if bytesAvail == 0 {
		return 0, err
	}

	totalBytesWritten := 0
	for {
		bytesWritten := copy(buf.chunks[chunkIdx][offset:], p[totalBytesWritten:])
		totalBytesWritten += bytesWritten
		chunkIdx++

		if chunkIdx == len(buf.chunks) {
			// Written the last chunk. Re-establish invariants and return.
			buf.writeOffset = offset + bytesWritten
			return totalBytesWritten, err
		}

		offset = 0
	}
}

func (buf *buffer) ReadFrom(r io.Reader) (totalBytesCopied int64, err error) {
	defer buf.repOk()

	defer func() {
		numChunks := len(buf.chunks)
		if numChunks == 0 {
			return
		}

		// Re-establish invariant: if we have an unused chunk, release it back to
		// the pool.
		if buf.writeOffset == 0 {
			buf.pool.release([][]byte{buf.chunks[numChunks-1]})
			buf.chunks = buf.chunks[:numChunks-1]
			buf.writeOffset = buf.pool.chunkSize_bytes
		}
	}()

	for {
		// Ensure there is space to write into.
		if len(buf.chunks) == 0 || buf.writeOffset == buf.pool.chunkSize_bytes {
			_, _, availBytes := buf.grow(buf.pool.chunkSize_bytes)
			if availBytes == 0 {
				return totalBytesCopied, ErrEmptyPool
			}
			buf.writeOffset = 0
		}

		// Copy into the next chunk.
		bytesCopied, err := r.Read(buf.chunks[len(buf.chunks)-1][buf.writeOffset:])
		if bytesCopied < 0 {
			panic(errNegativeRead)
		}

		buf.writeOffset += bytesCopied
		totalBytesCopied += int64(bytesCopied)
		if err == io.EOF {
			return totalBytesCopied, nil
		}
		if err != nil {
			return totalBytesCopied, err
		}
	}
}
