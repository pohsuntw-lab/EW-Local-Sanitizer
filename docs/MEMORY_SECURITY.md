# Memory security limitation

The encrypted dictionary, session and token-map implementations clear key and owned plaintext `Buffer` instances in `finally` blocks on normal and exception paths. Project scope secrets also have an explicit `dispose()` operation.

Node.js and JavaScript do not provide a reliable guarantee that strings, caller-owned objects, temporary serialization strings, garbage-collected copies or runtime-internal buffers are overwritten immediately. EW Local Sanitizer therefore does not claim complete memory zeroization. Raw values remain in memory only for the local processing lifetime needed to detect and transform them; default sessions are not persisted, and saved project/session artifacts must use authenticated local encryption.
