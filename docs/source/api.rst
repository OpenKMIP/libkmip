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
structure can

TBD

Client API
----------
TBD

.. code-block:: c

   #include <kmip/kmip_bio.h>

   int kmip_bio_create(BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_destroy(BIO *, char *, int);
   int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);

   int kmip_bio_create_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
   int kmip_bio_destroy_with_context(KMIP *, BIO *, char *, size_t);
   int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);

   int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *);

The client library API 

High-level API
~~~~~~~~~~~~~~
TBD

Mid-level API
~~~~~~~~~~~~~
TBD

Low-level API
~~~~~~~~~~~~~
TBD

Encoding API
------------
TBD

.. code-block:: c

   #include <kmip/kmip.h>

   int encode_request_message(KMIP *, const RequestMessage *);
   int decode_response_message(KMIP *, ResponseMessage *);

* TBD: There are a bunch of additional encoding/decoding functions but they are used internally by likmip. These two should be the only ones you need in practice.
* TBD: The return value of these two functions should be (discuss valid return types here).

Utilities API
-------------
TBD

The libkmip Context
~~~~~~~~~~~~~~~~~~~
The libkmip library context is a structure that contains all of the settings
and controls needed to create KMIP message encodings. It is defined in
``kmip.h``:

.. code-block:: c

   struct kmip
   {
       uint8 *buffer;
       uint8 *index;
       size_t size;

       enum kmip_version version;
       int max_message_size;
       LinkedList *credentials;

       char *error_message;
       size_t error_message_size;
       LinkedList *error_frames;

       void *(*calloc_func)(void *state, size_t num, size_t size);
       void *(*realloc_func)(void *state, void *ptr, size_t size);
       void  (*free_func)(void *state, void *ptr);
       void *(*memset_func)(void *ptr, int value, size_t size);
       void *state;
   };

The structure includes the encoding/decoding buffer, KMIP message settings,
error information, and memory management hooks.

The Encoding/Decoding Buffer
````````````````````````````
TBD

KMIP Message Settings
`````````````````````
TBD

Error Information
`````````````````
TBD

Memory Management
`````````````````
TBD

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