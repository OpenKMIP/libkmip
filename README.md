# libkmip - An ISO C11 implementation of KMIP

libkmip is an ISO C11 implementation of [KMIP][kmip], the Key Management
Interoperability Protocol. The library supports encoding and decoding KMIP
request and response messages for basic key management operations, including
creating, retrieving, and destroying symmetric keys. Retrieval and
destruction of public and private keys is also supported.

## Compilation

To build the library, use the included Makefile:

```
$ make
```

This will build four applications, including a library test suite and three
demo applications showing how to use the support KMIP operations.

To clean up build artifacts, use:

```
$ make clean
```

To clean up build artifacts and the built applications, use:

```
$ make cleanest
```

## Usage

The three demo applications will each connect to a KMIP server, establishing
a secure TLS connection, and then issue a KMIP request, receiving back the
corresponding KMIP response before parsing and displaying it to stdout. Note
that the configuration settings for these demo applications are currently
hard-coded into the application code. If you want to use these demos with
your own KMIP device, you will need to edit the source code accordingly.

The `demo_create` application will create a 256-bit AES symmetric key. To
run it, use:

```
$ ./demo_create
```

The `demo_get` application will retrieve a symmetric, public, or private key
using a provided ID string at the command line. To run it, use:

```
$ ./demo_get <id>
```

The `demo_destroy` application will destroy a KMIP managed object using a
provided ID string at the command line. To run it, use:

```
$ ./demo_destroy <id>
```

Finally, the `test` application will run the library unit test suite,
displaying the output results of each test and the overall test run to
stdout. To run it, use:

```
$ ./test
```

The test suite can also be run in an infinite loop as a basic harness to
test for memory leaks. To run it in this mode, use:

```
$ ./test 1
```

## Dependencies

libkmip currently depends on the OpenSSL BIO library to establish secure
connections to the KMIP server. OpenSSL and its source headers must be
installed and accessible for the libkmip build process to succeed.

## Installation

There is no current installation routine supported by the library makefile.
Installation will have to be done manually for the current code base. Future
versions will add installation routines in addition to support for building
a library shared object for dynamic builds.

[kmip]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip

