API
===
libkmip is composed of several components:

* an encoding/decoding library 
* a client library
* a utilities library

The encoding library transforms KMIP message structures to and from the KMIP
binary TTLV encoding format. The client library uses the `OpenSSL BIO library`_
to create secure connections with a KMIP server, sending and receiving
TTLV-encoded messages. Finally, the utilities library is used to create and
manage the library context and its associated structures which are used by the
client library. Together, these components can be used to conduct secure key
management operations.

KMIP operation requests are built by the client using libkmip structures,
transformed into a binary encoding using the libkmip encoding library, and
then sent to the target KMIP appliance using OpenSSL BIO. The target KMIP
appliance sends back an encoded KMIP operation response, which is decoded into
libkmip structures using the libkmip decoding library. The resulting response
structure can then be used by the parent application as needed.

.. _client-api:

Client API
----------
The libkmip client API supports varying levels of granularity, allowing parent
applications access to everything from the low-level encoded message buffer
up to high-level KMIP operation functions that handle all of the message
building and encoding details automatically.

The following function signatures define the client API and can be found in
``kmip_bio.h``:

.. code-block:: c

   /* High-level API */
   int kmip_bio_create(BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);
   int kmip_bio_destroy(BIO *, char *, int);
   
   /* Mid-level API */
   int kmip_bio_create_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);
   int kmip_bio_destroy_with_context(KMIP *, BIO *, char *, size_t);

   /* Low-level API */
   int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *); 

.. _high-level-api:

High-level API
~~~~~~~~~~~~~~
The high-level client API contains KMIP operation functions that simply
require the inputs for a specific KMIP operation. Using these functions, the
library will automatically:

* create the libkmip library context (see :ref:`the-libkmip-context`)
* create the request message structure
* encode the request message structure into a request encoding
* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* decode the response encoding into the response message structure
* extract the relevant output from the response message structure
* clean up the library context and the encoding buffers
* handle any errors that occur throughout the request/response process

Because the library context and encoding processes are handled internally, the
parent application has no access to additional debugging or error information
when the KMIP operation fails. There is also no way to control or manage the
dynamic memory allocation process required for the encoding buffers and the
decoding process. If this information and/or capability is needed by the
parent application, consider switching to use the :ref:`mid-level-api` or
:ref:`low-level-api` which provide these capabilities.

The function header details for each of the high-level API functions are
provided below.

.. c:function:: int kmip_bio_create(BIO *, TemplateAttribute *, char **, int *)

    Create a symmetric key with the attributes provided in the
    ``TemplateAttribute`` structure.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to the
        KMIP server that will create the symmetric key.
    :param TemplateAttribute*: A libkmip :class:`TemplateAttribute` structure
        containing the attributes for the symmetric key (e.g., cryptographic
        algorithm, cryptographic length).
    :param char**: A double pointer that can be used to access the UUID of the
        newly created symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the UUID.

    :param int*: A pointer that can be used to access the length of the UUID
        string pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``TemplateAttribute`` pointer is set to ``NULL``
            * the ``char **`` UUID double pointer is set to ``NULL``
            * the ``int *`` UUID size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key creation call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key creation call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *)

    Retrieve a symmetric key identified by a specific UUID.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to retrieve.
    :param int: The length of the above UUID string.
    :param char**: A double pointer that can be used to access the bytes of
        the retrieved symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the symmetric key.

    :param int*: A pointer that can be used to access the length of the
        symmetric key pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer
            * the ``char **`` bytes double pointer is set to ``NULL``
            * the ``int *`` bytes size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key retrieval call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key retrieval call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_destroy(BIO *, char *, int)

    Destroy a symmetric key identified by a specific UUID.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to destroy.
    :param int: The length of the above UUID string.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key destruction call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key destruction call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the default libkmip
            library context. Switching to the :ref:`mid-level-api` will
            allow the parent application to set the max message size in the
            library context directly.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. _mid-level-api:

Mid-level API
~~~~~~~~~~~~~
The mid-level client API is similar to the high-level API except that it
allows the parent application to create and supply the library context to
each KMIP operation function. This allows the parent application to set the
KMIP message settings relevant to its own use case, including the KMIP version
to use for message encoding, the maximum message size to accept from the KMIP
server, and the list of credentials to use when sending a KMIP request
message. The application can also substitute its own memory management system
using the standard memory function hooks provided in the context.

Should an error occur during the request encoding or response decoding
process, error information, including an error message and a stack trace
detailing the function call path triggering the error, can be obtained from
the library context. For more information on the context, see
:ref:`the-libkmip-context`.

Using these functions, the library will automatically:

* create the request message structure
* encode the request message structure into a request encoding
* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* decode the response encoding into the response message structure
* extract the relevant output from the response message structure
* clean up the encoding buffers
* handle any errors that occur throughout the request/response process

The function header details for each of the mid-level API functions are
provided below.

.. c:function:: int kmip_bio_create_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *)

    Create a symmetric key with the attributes provided in the
    ``TemplateAttribute`` structure.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to the
        KMIP server that will create the symmetric key.
    :param TemplateAttribute*: A libkmip :class:`TemplateAttribute` structure
        containing the attributes for the symmetric key (e.g., cryptographic
        algorithm, cryptographic length).
    :param char**: A double pointer that can be used to access the UUID of the
        newly created symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the UUID.

    :param int*: A pointer that can be used to access the length of the UUID
        string pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``TemplateAttribute`` pointer is set to ``NULL``
            * the ``char **`` UUID double pointer is set to ``NULL``
            * the ``int *`` UUID size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key creation call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key creation call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *)

    Retrieve a symmetric key identified by a specific UUID.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the symmetric key.
    :param char*: A string containing the UUID of the symmetric key to retrieve.
    :param int: The length of the above UUID string.
    :param char**: A double pointer that can be used to access the bytes of
        the retrieved symmetric key.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done using the symmetric key.

    :param int*: A pointer that can be used to access the length of the
        symmetric key pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer
            * the ``char **`` bytes double pointer is set to ``NULL``
            * the ``int *`` bytes size pointer is set to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key retrieval call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key retrieval call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. c:function:: int kmip_bio_destroy_with_context(KMIP *, BIO *, char *, int)

    Destroy a KMIP managed object identified by a specific UUID.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server that stores the KMIP managed object.
    :param char*: A string containing the UUID of the KMIP managed object to
        destroy.
    :param int: The length of the above UUID string.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function. If the code
        returned is not listed here, it is the result of the request encoding
        or response decoding process. See (ref here) for all possible status
        code values.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` UUID pointer is set to ``NULL``
            * the ``int`` UUID size argument is set to a non-positive integer

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during the key destruction call. This
            failure can occur during any of the following steps:

            * creation/resizing of the encoding buffer
            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during the key destruction call. This
            failure can occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

        * ``KMIP_MALFORMED_RESPONSE``
            The received response message from the KMIP server is malformed
            and does not contain valid operation result information.

.. _low-level-api:

Low-level API
~~~~~~~~~~~~~
The low-level client API differs from the mid and high-level APIs. It provides
a single function that is used to send and receive encoded KMIP messages. The
request message structure construction and encoding, along with the response
message structure decoding, is left up to the parent application. This provides
the parent application complete control over KMIP message processing.

Using this function, the library will automatically:

* send the request encoding to the BIO-connected KMIP server
* receive the response encoding back from the BIO-connected KMIP server
* handle any errors that occur throughout the send/receive process

The function header details for the low-level API function is provided below.

.. c:function:: int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *)

    Send a KMIP encoded request message to the KMIP server.

    :param KMIP*: A libkmip ``KMIP`` structure containing the context
        information needed to encode and decode message structures. Primarily
        used here to control the maximum response message size.

        .. note::
           This structure should be properly destroyed by the parent
           application once it is done conducting KMIP operations. See
           :ref:`the-libkmip-context` and :ref:`context-functions` for more
           information.

    :param BIO*: An OpenSSL ``BIO`` structure containing a connection to
        the KMIP server.
    :param char*: A string containing the KMIP encoded request message bytes.
    :param int: The length of the above encoded request message.
    :param char**: A double pointer that can be used to access the bytes of
        the received KMIP encoded response message.

        .. note::
           This pointer will point to a newly allocated block of memory. The
           parent application is responsible for clearing and freeing this
           memory once it is done processing the encoded response message.

    :param int*: A pointer that can be used to access the length of the
        encoded response message pointed to by the above double pointer.

    :return: A status code indicating success or failure of the operation. The
        following codes are returned explicitly by this function.

        * ``KMIP_ARG_INVALID``
            One or more of the function arguments are invalid or unset and no
            work can be done. This failure can occur if any of the following
            are true:

            * the libkmip ``KMIP`` pointer is set to ``NULL``
            * the OpenSSL ``BIO`` pointer is set to ``NULL``
            * the ``char *`` encoded request message bytes pointer is set to
              ``NULL``
            * the ``int`` encoded request message bytes size argument is set
              to a non-positive integer
            * the ``char **`` encoded response message bytes double pointer is
              set to ``NULL``
            * the ``int *`` encoded response message bytes size pointer is set
              to ``NULL``

        * ``KMIP_MEMORY_ALLOC_FAILED``
            Memory allocation failed during message handling. This failure can
            occur during the following step:

            * creation of the decoding buffer

        * ``KMIP_IO_FAILURE``
            A ``BIO`` error occurred during message handling. This failure can
            occur during any of the following steps:

            * sending the encoded request message to the KMIP server
            * receiving the encoded response message from the KMIP server

        * ``KMIP_EXCEED_MAX_MESSAGE_SIZE``
            The received response message from the KMIP server exceeds the
            maximum allowed message size defined in the provided libkmip
            library context.

.. _encoding-api:

Encoding API
------------
The libkmip encoding API supports encoding and decoding a variety of message
structures and substructures to and from the KMIP TTLV encoding format. The
:ref:`client-api` functions use the resulting encoded messages to communicate
KMIP operation instructions to the KMIP server. While each substructure
contained in a request or response message structure has its own corresponding
set of encoding and decoding functions, parent applications using libkmip
should only need to use the encoding and decoding functions for request and
response messages respectively.

The following function signatures define the encoding API and can be found in
``kmip.h``:

.. code-block:: c

   int kmip_encode_request_message(KMIP *, const RequestMessage *);
   int kmip_decode_response_message(KMIP *, ResponseMessage *);

The function header details for each of the encoding API functions are
provided below.

.. c:function:: int kmip_encode_request_message(KMIP *, const RequestMessage *)

.. c:function:: int kmip_decode_response_message(KMIP *, ResponseMessage *)

.. _utilities-api:

Utilities API
-------------
TBD

.. _the-libkmip-context:

The libkmip Context
~~~~~~~~~~~~~~~~~~~
The libkmip library context is a structure that contains all of the settings
and controls needed to create KMIP message encodings. It is defined in
``kmip.h``:

.. code-block:: c

   typedef struct kmip
   {
       /* Encoding buffer */
       uint8 *buffer;
       uint8 *index;
       size_t size;

       /* KMIP message settings */
       enum kmip_version version;
       int max_message_size;
       LinkedList *credentials;

       /* Error handling information */
       char *error_message;
       size_t error_message_size;
       LinkedList *error_frames;

       /* Memory management function pointers */
       void *(*calloc_func)(void *state, size_t num, size_t size);
       void *(*realloc_func)(void *state, void *ptr, size_t size);
       void  (*free_func)(void *state, void *ptr);
       void *(*memset_func)(void *ptr, int value, size_t size);
       void *state;
   } KMIP;

The structure includes the encoding/decoding buffer, KMIP message settings,
error information, and memory management hooks.

The Encoding/Decoding Buffer
````````````````````````````
The library context contains a pointer to the main target buffer, ``buffer``,
used for both encoding and decoding KMIP messages. This buffer should only
be set and accessed using the defined context utility functions defined below.
It should never be accessed or manipulated directly.

KMIP Message Settings
`````````````````````
The library context contains several attributes that are used throughout the
encoding and decoding process to control what KMIP structures are included in
operation request and response messages. The ``version`` enum attribute should
be set by the parent application to the desired KMIP version:

.. code-block:: c

   enum kmip_version
   {
       KMIP_1_0 = 0,
       KMIP_1_1 = 1,
       KMIP_1_2 = 2,
       KMIP_1_3 = 3,
       KMIP_1_4 = 4
   };

The ``max_message_size`` attribute defines the maximum size allowed for
incoming response messages. Since KMIP message encodings define the total size
of the message at the beginning of the encoding, it is important for the 
parent application to set this attribute to a reasonable default suitable for
its operation.

The ``credentials`` list is intended to store a set of authentication
credentials that should be included in any request message created with the
library context. This is primarily intended for use with the mid-level client
API (TBD link here).

Each of these attributes will be set to reasonable defaults by the
``kmip_init`` context utility and can be overridden as needed.

Error Information
`````````````````
The library context contains several attributes that are used to track and
store error information. These are only used when errors occur during the
encoding or decoding process. Once an error is detected, a libkmip stack
trace will be constructed, with each frame in the stack containing the
function name and source line number where the error occurred to facilitate
debugging.

.. code-block:: c

   typedef struct error_frame
   {
       char *function;
       int line;
   } ErrorFrame;

The original error message will be captured in the ``error_message``
attribute for use in logging or user-facing status messages.

TBD - See the context functions below for using and accessing this error information.


Memory Management
`````````````````
The library context contains several function pointers that can be used to
wrap or substitute common memory management utilities. All memory management
done by libkmip is done through these function pointers, allowing the calling
application to easily substitute its own memory management system. The
``kmip_init`` utility function will automatically set these hooks to the default memory
management functions if any of them are unset.

.. _context-functions:

Context Functions
~~~~~~~~~~~~~~~~~
TBD

.. code-block:: c

   #include <kmip/kmip.h>

   void kmip_clear_errors(KMIP *);
   void kmip_init(KMIP *, void *, size_t, enum kmip_version);
   void kmip_init_error_message(KMIP *);
   int  kmip_add_credential(KMIP *, Credential *);
   void kmip_remove_credentials(KMIP *);
   void kmip_reset(KMIP *);
   void kmip_rewind(KMIP *);
   void kmip_set_buffer(KMIP *, void *, size_t);
   void kmip_destroy(KMIP *);
   void kmip_push_error_frame(KMIP *, const char *, const int);

ADD REMAINING FUNCTIONS HERE

ADD MORE DETAILS HERE

.. _`OpenSSL BIO library`: https://www.openssl.org/docs/man1.1.0/crypto/bio.html