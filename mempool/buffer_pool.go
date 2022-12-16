package mempool

import (
	"fmt"
)

// A factory of variable-sized buffers whose backing storage is drawn from a
// fixed-sized pool. Clients must return the backing storage for all buffers
// obtained from this pool by calling Reset on the buffer.
type BufferPool interface {
	// Returns a new empty buffer
	NewBuffer() Buffer
}

// Creates a new buffer pool. Up to maxPoolSize_bytes of buffer chunks will be
// pooled. Each buffer chunk will have size chunkSize_bytes.
func MakeBufferPool(maxPoolSize_bytes int64, chunkSize_bytes int64) (BufferPool, error) {
	if chunkSize_bytes < 1 {
		return nil, fmt.Errorf("invalid chunkSize_bytes %d", chunkSize_bytes)
	}
	if maxPoolSize_bytes < chunkSize_bytes {
		return nil, fmt.Errorf("invalid maxPoolSize_bytes %d", maxPoolSize_bytes)
	}

	numChunks := maxPoolSize_bytes / chunkSize_bytes
	chunks := make(chan []byte, numChunks)
	for count := 0; count < int(numChunks); count++ {
		chunks <- make([]byte, chunkSize_bytes)
	}

	return bufferPool{
		chunks:          chunks,
		chunkSize_bytes: int(chunkSize_bytes),
	}, nil
}

type bufferPool struct {
	// Stores all available chunks.
	chunks chan []byte

	// The size of each chunk, in bytes.
	chunkSize_bytes int
}

var _ BufferPool = (*bufferPool)(nil)

func (pool bufferPool) NewBuffer() Buffer {
	return newBuffer(pool)
}

// Obtains a chunk from the pool. Returns nil if the pool is empty.
func (pool bufferPool) getChunk() []byte {
	select {
	case result := <-pool.chunks:
		for i := range result {
			result[i] = 0
		}
		return result
	default:
		return nil
	}
}

// Releases the given chunks back to the pool.
func (pool bufferPool) release(chunks [][]byte) {
	// Avoid blocking, in case we somehow end up releasing more chunks than were
	// initially allocated for the pool.
	for _, chunk := range chunks {
		select {
		case pool.chunks <- chunk:
			continue
		default:
			return
		}
	}
}
