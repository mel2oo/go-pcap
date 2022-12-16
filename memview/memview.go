package memview

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

// MemView represents a "view" on a collection of byte slices. Conceptually, you
// may think of it as a [][]byte, with helper methods to make it seem like one
// contiguous []byte. It is designed to help minimize the amount of copying when
// dealing with large buffers of data.
//
// Modifying a MemView does not change the underlying data. Instead, it simply
// changes the pointers to where to read data from.
//
// Copying a MemView or passing memView by value is like copying a slice - it's
// efficient, but modifications to the copy affect the original MemView and vice
// versa. Use `DeepCopy` to create a completely independent MemView.
//
// The zero value is an empty MemView ready to use.
type MemView struct {
	buf    [][]byte
	length int64
}

// The new MemView does NOT make a copy of data, so the caller MUST ensure that
// the underlying memory of data remains valid and unmodified after this call
// returns.
func New(data []byte) MemView {
	return MemView{
		buf:    [][]byte{data},
		length: int64(len(data)),
	}
}

// Make an empty memview
func Empty() MemView {
	return MemView{
		buf:    [][]byte{},
		length: 0,
	}
}

func (dst *MemView) Append(src MemView) {
	dst.buf = append(dst.buf, src.buf...)
	dst.length += src.length
}

// Creates a MemView that is completely independent from the current one.
func (mv MemView) DeepCopy() MemView {
	newBuf := make([][]byte, len(mv.buf))
	copy(newBuf, mv.buf)
	return MemView{
		buf:    newBuf,
		length: mv.length,
	}
}

func (mv *MemView) CreateReader() *MemViewReader {
	return &MemViewReader{mv: mv}
}

func (mv *MemView) Clear() {
	mv.buf = mv.buf[:0] // clear without reallocating memory
	mv.length = 0
}

func (mv MemView) Len() int64 {
	return mv.length
}

// Returns the byte at the given index. Returns 0 if index is out of bounds.
func (mv MemView) GetByte(index int64) byte {
	if index < 0 {
		return 0
	}

	n := index
	for i := 0; i < len(mv.buf); i++ {
		lb := int64(len(mv.buf[i]))
		if n < lb {
			return mv.buf[i][n]
		}
		n -= lb
	}
	return 0
}

// Returns a copy of mv[start:end]. Returns nil if start is negative, start >
// end, or end is out of bounds.
func (mv MemView) getBytes(start, end int64) []byte {
	if !(0 <= start && start <= end && end <= mv.Len()) {
		return nil
	}

	result := make([]byte, end-start)
	resultIdx := int64(0) // Points to the next result byte to be written.

	for bufIdx := 0; bufIdx < len(mv.buf) && start < end; bufIdx++ {
		bufLen := int64(len(mv.buf[bufIdx]))
		if start >= bufLen {
			// Current buffer is before the part to be copied.
			start -= bufLen
			end -= bufLen
			continue
		}

		copyEnd := end
		if copyEnd > bufLen {
			copyEnd = bufLen
		}

		copy(result[resultIdx:], mv.buf[bufIdx][start:copyEnd])

		copySize := copyEnd - start
		start = 0
		end -= bufLen
		resultIdx += copySize
	}

	return result
}

// Returns mv[offset:offset+2], interpreted as a uint16 in network (big endian)
// order. Returns 0 if offset+1 is out of bounds.
func (mv MemView) GetUint16(offset int64) uint16 {
	buf := mv.getBytes(offset, offset+2)
	if buf == nil {
		return 0
	}
	return binary.BigEndian.Uint16(buf)
}

// Returns mv[offset:offset+3], interpreted as an unsigned 24-bit integer in
// network (big endian) order. Returns 0 if offset+2 is out of bounds.
func (mv MemView) GetUint24(offset int64) uint32 {
	buf := mv.getBytes(offset, offset+3)
	if buf == nil {
		return 0
	}
	buf = append([]byte{0}, buf...)
	return binary.BigEndian.Uint32(buf)
}

// Returns mv[offset:offset+4], interpreted as a uint32 in network (big endian)
// order. Returns 0 if offset+3 is out of bounds.
func (mv MemView) GetUint32(offset int64) uint32 {
	buf := mv.getBytes(offset, offset+4)
	if buf == nil {
		return 0
	}
	return binary.BigEndian.Uint32(buf)
}

// Returns mv[start:end] (end is not inclusive). Returns an empty MemView if
// range is invalid.
func (mv MemView) SubView(start, end int64) MemView {
	if start >= end {
		return MemView{}
	}

	startBuf := -1
	endBuf := -1
	var startOffset, endOffset int

	var n int64
	for i, b := range mv.buf {
		lb := int64(len(b))
		if startBuf == -1 && n+lb > start {
			startBuf = i
			startOffset = int(start - n)
		}
		if endBuf == -1 && n+lb >= end { // >= because end is not inclusive
			endBuf = i
			endOffset = int(end - n)
			break
		}
		n += lb
	}

	if startBuf == -1 || endBuf == -1 {
		return MemView{}
	}

	newBuf := make([][]byte, endBuf+1-startBuf)
	copy(newBuf, mv.buf[startBuf:endBuf+1])
	newMS := MemView{
		buf:    newBuf,
		length: end - start,
	}
	if len(newMS.buf) == 1 {
		newMS.buf[0] = newMS.buf[0][startOffset:endOffset]
	} else {
		newMS.buf[0] = newMS.buf[0][startOffset:]
		newMS.buf[len(newMS.buf)-1] = newMS.buf[len(newMS.buf)-1][:endOffset]
	}
	return newMS
}

// Index returns the index of the first instance of sep in mv after start index,
// or -1 if sep is not present in mv.
func (mv MemView) Index(start int64, sep []byte) int64 {
	// Find the first buffer to start from.
	startBuf := -1
	startOffset := 0
	var currIndex int64
	for i, b := range mv.buf {
		lb := int64(len(b))
		if currIndex+lb-1 < start { // -1 because start is an index
			currIndex += lb
		} else {
			startBuf = i
			startOffset = int(start - currIndex)
			currIndex += int64(startOffset)
			break
		}
	}

	if startBuf == -1 {
		return -1
	} else if len(sep) == 0 {
		return start
	}

	// Iteratively search for the target, keeping in mind that the target may be
	// spread over multiple slices in mv.buf.
	//
	// TODO: this only works correctly for search strings that do not have a repeated
	// prefix. To work correctly, we would have to back up to the point at which
	// the needle *could* have started after an incomplete match.
	//
	// However, we only use this method to search for strings without a repeated prefix:
	// GET, POST, DELETE, HEAD, PUT, PATCH, CONNECT, OPTIONS, TRACE, HTTP/1.1 and HTTP/1.0
	needle := sep
	needleIndex := 0
	for b := startBuf; b < len(mv.buf); b++ {
		haystack := mv.buf[b]
		// Check remainder of needle if overlap from last buffer
		var i int = 0
		for i = startOffset; i < len(haystack) && needleIndex > 0; i++ {
			if haystack[i] == needle[needleIndex] {
				needleIndex += 1
				if needleIndex == len(needle) {
					// Found, figure out start index.
					// At the start of the 'i' loop, it points to currentIndex, so we
					// need to add i and subtract startOffset.  Then move back to the
					// first character in the needle
					return currIndex + int64(i-startOffset) - int64(len(needle)-1)
				}
			} else {
				needleIndex = 0
			}
		}

		// Did we reach the end of the buffer already?
		if i < len(haystack) {
			// If not, efficient check of remaining portion of haystack
			found := bytes.Index(haystack[i:], needle)
			if found != -1 {
				return currIndex + int64(found)
			}

			// Check the end of the haystack for the start of the needle
			// (but not the whole thing, or we would have found it in the call above.)
			needleStart := len(haystack) - len(needle) + 1
			if i < needleStart {
				i = needleStart
			}
			for ; i < len(haystack); i++ {
				if haystack[i] == needle[needleIndex] {
					needleIndex += 1
				} else {
					needleIndex = 0
				}
			}
		}

		// Searched all of buffer
		currIndex += int64(len(haystack) - startOffset)
		startOffset = 0
	}

	return -1
}

// Returns a string of all the data referenced by this MemView. Note that is
// creates a COPY of the underlying data.
func (mv MemView) String() string {
	var buf bytes.Buffer
	io.Copy(&buf, mv.CreateReader())
	return buf.String()
}

type MemViewReader struct {
	mv *MemView

	// Index for the element from mv.buf to read next.
	rIndex int

	// Offset into mv.buf[rIndex] for the next read.
	rOffset int

	// Global offset into mv for the next read.
	gOffset int64
}

var _ io.ReadSeeker = (*MemViewReader)(nil)

func (r *MemViewReader) ReadByte() (byte, error) {
	if r.rIndex >= len(r.mv.buf) {
		return 0, io.EOF
	}

	for i := r.rIndex; i < len(r.mv.buf); i++ {
		curBuf := r.mv.buf[r.rIndex]
		if r.rOffset < len(curBuf) {
			result := curBuf[r.rOffset]
			r.rOffset++
			r.gOffset++
			return result, nil
		} else {
			r.rIndex++
			r.rOffset = 0
		}
	}

	return 0, io.EOF
}

// Seeks past a variable-length field by reading the next byte value and seeking
// that number of bytes.
func (r *MemViewReader) ReadByteAndSeek() error {
	length, err := r.ReadByte()
	if err != nil {
		return err
	}
	_, err = r.Seek(int64(length), io.SeekCurrent)
	return err
}

func (r *MemViewReader) ReadUint16() (uint16, error) {
	buf := make([]byte, 2)
	read, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	if read != len(buf) {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint16(buf), nil
}

// Seeks past a variable-length field by reading the next uint16 value and
// seeking that number of bytes.
func (r *MemViewReader) ReadUint16AndSeek() error {
	length, err := r.ReadUint16()
	if err != nil {
		return err
	}
	_, err = r.Seek(int64(length), io.SeekCurrent)
	return err
}

// Returns a new reader for a field whose length is indicated by the next uint16
// value, and the length of that field. On return, this reader will have its
// position advanced by two bytes and the returned reader will be the result of
// truncating to the field's length.
func (r *MemViewReader) ReadUint16AndTruncate() (length uint16, fieldReader *MemViewReader, err error) {
	length, err = r.ReadUint16()
	if err != nil {
		return 0, nil, err
	}
	fieldReader, err = r.Truncate(int64(length))
	return length, fieldReader, err
}

func (r *MemViewReader) ReadUint24() (uint32, error) {
	buf := make([]byte, 3)
	read, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	if read != len(buf) {
		return 0, io.EOF
	}
	buf = append([]byte{0}, buf...)
	return binary.BigEndian.Uint32(buf), nil
}

// Returns a new reader for a field whose length is indicated by the next uint24
// value, and the length of that field. On return, this reader will have its
// position advanced by three bytes and the returned reader will be the result
// of truncating to the field's length.
func (r *MemViewReader) ReadUint24AndTruncate() (length uint32, fieldReader *MemViewReader, err error) {
	length, err = r.ReadUint24()
	if err != nil {
		return 0, nil, err
	}
	fieldReader, err = r.Truncate(int64(length))
	return length, fieldReader, err
}

func (r *MemViewReader) ReadUint32() (uint32, error) {
	buf := make([]byte, 4)
	read, err := r.Read(buf)
	if err != nil {
		return 0, err
	}
	if read != len(buf) {
		return 0, io.EOF
	}
	return binary.BigEndian.Uint32(buf), nil
}

// Reads a string of the given length.
func (r *MemViewReader) ReadString(length int) (string, error) {
	result := make([]byte, length)
	read, err := r.Read(result)
	if err != nil {
		return "", err
	}

	if read != int(length) {
		return "", io.EOF
	}
	return string(result), nil
}

// Reads a string whose length is indicated by the next byte.
func (r *MemViewReader) ReadString_byte() (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	return r.ReadString(int(length))
}

// Reads a string whose length is indicated by the next uint16.
func (r *MemViewReader) ReadString_uint16() (string, error) {
	length, err := r.ReadUint16()
	if err != nil {
		return "", err
	}
	return r.ReadString(int(length))
}

// If MemView has no data to return, err is io.EOF (unless len(out) is zero),
// otherwise it is nil. This behavior matches that of bytes.Buffer.
func (r *MemViewReader) Read(out []byte) (int, error) {
	if len(out) == 0 {
		return 0, nil
	} else if r.rIndex >= len(r.mv.buf) { // really just ==, but use >= to be safer
		return 0, io.EOF
	}

	bytesRead := 0
	for i := r.rIndex; i < len(r.mv.buf); i++ {
		curr := r.mv.buf[i][r.rOffset:]
		cp := copy(out[bytesRead:], curr)
		bytesRead += cp
		if cp == len(curr) {
			r.rIndex += 1
			r.rOffset = 0
			r.gOffset += int64(cp)
		} else {
			// If cp < len(curr), it means we've run out of output space.
			r.rOffset += cp
			r.gOffset += int64(cp)
			return bytesRead, nil
		}
	}

	// We've read something, so don't return EOF in case more data gets passed to
	// this MemView.
	return bytesRead, nil
}

// Implements ReadSeeker.Seek.
func (r *MemViewReader) Seek(offset int64, whence int) (absoluteOffset int64, err error) {
	// Save the reader's state. If we fail, restore that state.
	{
		rIndex, rOffset, gOffset := r.rIndex, r.rOffset, r.gOffset
		defer func() {
			if err != nil {
				r.rIndex, r.rOffset, r.gOffset = rIndex, rOffset, gOffset
			}
		}()
	}

	switch whence {
	case io.SeekStart:
		// Convert to SeekCurrent.
		r.rIndex, r.rOffset, r.gOffset = 0, 0, 0 // set to the beginning
		return r.Seek(offset, io.SeekCurrent)

	case io.SeekEnd:
		// Convert to SeekCurrent.
		r.rIndex, r.rOffset, r.gOffset = len(r.mv.buf), 0, r.mv.length // set to the end
		return r.Seek(offset, io.SeekCurrent)

	case io.SeekCurrent:
		for {
			if offset == 0 {
				return r.gOffset, nil
			}

			// See if we can stay within the current block (if we haven't moved beyond
			// the last block).
			if r.rIndex < len(r.mv.buf) {
				newROffset := int64(r.rOffset) + offset
				if 0 <= newROffset && newROffset < int64(len(r.mv.buf[r.rIndex])) {
					r.rOffset += int(offset)
					r.gOffset += offset
					return r.gOffset, nil
				}
			}

			if offset < 0 {
				// Seeking backwards. Go to the end of the previous block.
				offset += int64(r.rOffset)
				r.gOffset -= int64(r.rOffset)
				r.rIndex--
				if r.rIndex < 0 {
					return 0, errors.New("MemViewReader.Seek: negative position")
				}
				r.rOffset = len(r.mv.buf[r.rIndex])
			} else if r.rIndex < len(r.mv.buf) {
				// Seeking forwards. Go to the beginning of the next block.
				curBuf := r.mv.buf[r.rIndex]
				numSkipped := len(curBuf) - r.rOffset
				offset -= int64(numSkipped)
				r.gOffset += int64(numSkipped)
				r.rIndex++
				r.rOffset = 0
			} else {
				// Seeking forwards, but we've moved past the last block.
				return r.gOffset, nil
			}
		}

	default:
		return 0, errors.New("MemViewReader.Seek: invalid whence")
	}
}

// Returns a copy of this MemViewReader, except the underlying MemView is a
// subview from the current position to the given relative offset. Returns an
// error if the offset is negative or is past the end of the current MemView.
func (r *MemViewReader) Truncate(offset int64) (*MemViewReader, error) {
	endPos := r.gOffset + offset
	if offset < 0 || r.gOffset+offset > r.mv.length {
		return nil, errors.Errorf("MemViewReader.Truncate: invalid offset")
	}

	subView := r.mv.SubView(r.gOffset, endPos)
	return subView.CreateReader(), nil
}

// Make MemView more efficient as a source in io.Copy.
func (r *MemViewReader) WriteTo(dst io.Writer) (int64, error) {
	var bytesWritten int64
	for _, b := range r.mv.buf {
		n, err := dst.Write(b)
		bytesWritten += int64(n)
		if err != nil {
			return bytesWritten, err
		}
	}
	return bytesWritten, nil
}

func (left MemView) Equal(right MemView) bool {
	if left.length != right.length {
		return false
	}

	leftBufIdx := 0
	leftBufOffset := 0
	rightBufIdx := 0
	rightBufOffset := 0
	for idx := int64(0); idx < left.length; idx++ {
		// Assume both MemViews are internally consistent, so we don't need to do
		// any bounds checks on left.buf and right.buf.

		// Seek through the buffers on each side until we find the next byte.
		for leftBufOffset >= len(left.buf[leftBufIdx]) {
			leftBufIdx++
			leftBufOffset = 0
		}
		for rightBufOffset >= len(right.buf[rightBufIdx]) {
			rightBufIdx++
			rightBufOffset = 0
		}

		if left.buf[leftBufIdx][leftBufOffset] != right.buf[rightBufIdx][rightBufOffset] {
			return false
		}

		leftBufOffset++
		rightBufOffset++
	}

	return true
}
