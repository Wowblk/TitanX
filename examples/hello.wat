(module
  ;; Import WASI fd_write for stdout.
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))

  (memory (export "memory") 1)

  ;; iovec buffer at offset 0:
  ;; - ptr to string data at 8
  ;; - len of string data
  (data (i32.const 8) "Hello from Titanclaw WASI!\n")

  (func $_start (export "_start")
    ;; iovec.buf = 8
    (i32.store (i32.const 0) (i32.const 8))
    ;; iovec.buf_len = 27
    (i32.store (i32.const 4) (i32.const 27))

    ;; fd_write(fd=1, iovs=0, iovs_len=1, nwritten=32)
    (drop
      (call $fd_write
        (i32.const 1)
        (i32.const 0)
        (i32.const 1)
        (i32.const 32))))
)
