package mempool

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mel2oo/go-pcap/memview"
	"github.com/stretchr/testify/assert"
)

func TestMakeBufferPool(t *testing.T) {
	// Enable invariant-checking.
	CheckInvariants = true

	tests := []struct {
		name              string
		maxPoolSize_bytes int64
		chunkSize_bytes   int64
		expectError       bool
	}{
		{
			name:              "Negative chunk size",
			maxPoolSize_bytes: 1024,
			chunkSize_bytes:   -1,
			expectError:       true,
		},
		{
			name:              "Zero chunk size",
			maxPoolSize_bytes: 1024,
			chunkSize_bytes:   0,
			expectError:       true,
		},
		{
			name:              "Max pool size smaller than chunk size",
			maxPoolSize_bytes: 1024,
			chunkSize_bytes:   1025,
			expectError:       true,
		},
		{
			name:              "Max pool size equal to chunk size",
			maxPoolSize_bytes: 1024,
			chunkSize_bytes:   1024,
		},
		{
			name:              "Max pool size larger than chunk size",
			maxPoolSize_bytes: 1025,
			chunkSize_bytes:   1024,
		},
	}

	for _, testCase := range tests {
		_, err := MakeBufferPool(testCase.maxPoolSize_bytes, testCase.chunkSize_bytes)
		if testCase.expectError {
			assert.Error(t, err, testCase.name)
		} else {
			assert.NoError(t, err, testCase.name)
		}
	}
}

// Tests the behaviour of buffer.ReadFrom, buffer.Read, and buffer.Write.
func TestReadWrite(t *testing.T) {
	// Enable invariant-checking.
	CheckInvariants = true

	for _, testCase := range readWriteTests {
		testCase.run(t)
	}
}

// Each test case creates some buffers from a pool and performs a sequence of
// writes to those buffers. After each write, the contents of each buffer is
// compared with that of a reference implementation.
type testCase struct {
	name              string
	maxPoolSize_bytes int64
	chunkSize_bytes   int64
	numBuffers        int
	writes            []writeSpec
}

type writeSpec struct {
	bufferIdx           int
	amountToWrite       int
	expectedWriteAmount int

	// Expected error if writing with Write.
	expectedWriteError error

	// Expected error if writing with ReadFrom.
	expectedReadFromError error
}

func (testCase testCase) run(t *testing.T) {
	// Run the test case once using buffer.Write and again with buffer.ReadFrom.
	for _, writeMode := range []string{"Write", "ReadFrom"} {
		// Seed the PRNG so that the test is deterministic.
		rand.Seed(0)

		// Create the buffer pool.
		pool, err := MakeBufferPool(testCase.maxPoolSize_bytes, testCase.chunkSize_bytes)
		assert.NoError(t, err, testCase.name)

		// Create buffers. Each buffer has a corresponding instance of bytes.Buffer
		// that will contain the expected contents of that buffer.
		buffers := make([]Buffer, testCase.numBuffers)
		expectedBuffers := make([]*bytes.Buffer, testCase.numBuffers)
		for idx := range buffers {
			buffers[idx] = pool.NewBuffer()
			expectedBuffers[idx] = &bytes.Buffer{}
		}

		// Write to the buffers and check the resulting contents of the buffer.
		for writeIdx, write := range testCase.writes {
			writeNum := writeIdx + 1

			// Create a randomized payload to be written.
			payload := make([]byte, write.amountToWrite)
			for i := range payload {
				payload[i] = byte(rand.Int())
			}

			// Write to the chosen buffer.
			var n int64
			var err, expectedError error
			buf := buffers[write.bufferIdx]
			switch writeMode {
			case "Write":
				nWritten, writeErr := buf.Write(payload)
				n = int64(nWritten)
				err = writeErr
				expectedError = write.expectedWriteError
			case "ReadFrom":
				payloadMemView := memview.New(payload)
				n, err = buf.ReadFrom(payloadMemView.CreateReader())
				expectedError = write.expectedReadFromError
			}
			assert.Equalf(t, int64(write.expectedWriteAmount), n, "%s, %s #%d", testCase.name, writeMode, writeNum)
			assert.Equalf(t, expectedError, err, "%s, %s #%d", testCase.name, writeMode, writeNum)

			// Write to the corresponding bytes.Buffer.
			expectedBuf := expectedBuffers[write.bufferIdx]
			actualWrite, err := expectedBuf.Write(payload[:n])
			assert.Equalf(t, write.expectedWriteAmount, actualWrite, "%s, write #%d to bytes.Buffer", testCase.name, writeNum)
			assert.NoErrorf(t, err, "%s, write #%d to bytes.Buffer", testCase.name, writeNum)

			// Compare the contents of each buffer with its corresponding
			// bytes.Buffer.
			for idx := range buffers {
				buf := buffers[idx]
				expectedBuf := expectedBuffers[idx]
				bufMemView := buf.Bytes()
				var expectedMemView memview.MemView
				if expectedBuf.Len() > 0 {
					expectedMemView = memview.New(expectedBuf.Bytes())
				}

				diff := cmp.Diff(expectedMemView, bufMemView)
				if diff != "" {
					t.Errorf("%s, after %s #%d, comparing buffers[%d], found diff: %s", testCase.name, writeMode, writeNum, idx, diff)
				}
			}
		}

		// Release the buffers.
		for _, buf := range buffers {
			buf.Release()
		}
	}
}

// Test cases for testing reading and writing.
var readWriteTests = []testCase{
	{
		name:              "1-chunk pool (1)",
		maxPoolSize_bytes: 11,
		chunkSize_bytes:   10,
		numBuffers:        2,
		writes: []writeSpec{
			// Perform empty writes to each buffer.
			{bufferIdx: 0},
			{bufferIdx: 1},

			// Allocate the only chunk to buffer 0 and fill it.
			{
				bufferIdx:           0,
				amountToWrite:       10,
				expectedWriteAmount: 10,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt to write more to buffer 0.
			{
				bufferIdx:             0,
				amountToWrite:         1,
				expectedWriteAmount:   0,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt to write to buffer 1.
			{
				bufferIdx:             1,
				amountToWrite:         1,
				expectedWriteAmount:   0,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt empty writes to both buffers.
			{
				bufferIdx: 0,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},
			{
				bufferIdx: 1,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "1-chunk pool (2)",
		maxPoolSize_bytes: 11,
		chunkSize_bytes:   10,
		numBuffers:        2,
		writes: []writeSpec{
			// Perform empty writes to each buffer.
			{bufferIdx: 0},
			{bufferIdx: 1},

			// Allocate the only chunk to buffer 0 and write a byte to it.
			{
				bufferIdx:           0,
				amountToWrite:       1,
				expectedWriteAmount: 1,
			},

			// Attempt to write to buffer 1.
			{
				bufferIdx:             1,
				amountToWrite:         1,
				expectedWriteAmount:   0,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt to over-fill buffer 0.
			{
				bufferIdx:             0,
				amountToWrite:         10,
				expectedWriteAmount:   9,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt empty writes to both buffers.
			{
				bufferIdx: 0,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},
			{
				bufferIdx: 1,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "2-chunk pool, 1 buffer (1)",
		maxPoolSize_bytes: 20,
		chunkSize_bytes:   10,
		numBuffers:        1,
		writes: []writeSpec{
			// Allocate both chunks to the buffer and write 11 bytes.
			{
				amountToWrite:       11,
				expectedWriteAmount: 11,
			},

			// Attempt to over-fill the buffer.
			{
				amountToWrite:         10,
				expectedWriteAmount:   9,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "2-chunk pool, 1 buffer (2)",
		maxPoolSize_bytes: 20,
		chunkSize_bytes:   10,
		numBuffers:        1,
		writes: []writeSpec{
			// Allocate both chunks to the buffer and fill them.
			{
				amountToWrite:       20,
				expectedWriteAmount: 20,
				// We get EmptyPool any time ReadFrom fills the last chunk exactly.
				expectedReadFromError: ErrEmptyPool,
			},

			// Attempt to write more.
			{
				amountToWrite:         1,
				expectedWriteAmount:   0,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "2-chunk pool, 1 buffer (3)",
		maxPoolSize_bytes: 20,
		chunkSize_bytes:   10,
		numBuffers:        1,
		writes: []writeSpec{
			// Allocate both chunks to the buffer and attempt to over-fill it.
			{
				amountToWrite:         21,
				expectedWriteAmount:   20,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "2-chunk pool, 2 buffers (1)",
		maxPoolSize_bytes: 20,
		chunkSize_bytes:   10,
		numBuffers:        2,
		writes: []writeSpec{
			// Allocate one chunk to each buffer and write a byte to each.
			{
				bufferIdx:           0,
				amountToWrite:       1,
				expectedWriteAmount: 1,
			},
			{
				bufferIdx:           1,
				amountToWrite:       1,
				expectedWriteAmount: 1,
			},

			// Attempt to over-fill each buffer.
			{
				bufferIdx:             0,
				amountToWrite:         10,
				expectedWriteAmount:   9,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},
			{
				bufferIdx:             1,
				amountToWrite:         10,
				expectedWriteAmount:   9,
				expectedWriteError:    ErrEmptyPool,
				expectedReadFromError: ErrEmptyPool,
			},
		},
	},
	{
		name:              "2-chunk pool, 2 buffers (2)",
		maxPoolSize_bytes: 20,
		chunkSize_bytes:   10,
		numBuffers:        2,
		writes: []writeSpec{
			// Allocate one chunk to buffer 0 and fill it. Internally, the ReadFrom
			// case will allocate both chunks to the buffer, discover that the second
			// chunk is unneeded, and release it back to the pool.
			{
				bufferIdx:           0,
				amountToWrite:       10,
				expectedWriteAmount: 10,
			},

			// Allocate the other chunk to buffer 1.
			{
				bufferIdx:           1,
				amountToWrite:       1,
				expectedWriteAmount: 1,
			},
		},
	},
}
