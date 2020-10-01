Overview
========

This library implements core components required to implement `Sidetree Protocol: <https://github.com/decentralized-identity/sidetree/blob/master/docs/protocol.md>`_


Batch Writer
------------
Batch writer batches multiple document operations(create, update, delete, recover) in a single batch file. Batch files are stored in a distributed content-addressable storage (DCAS or CAS). A reference to the operation batch is then anchored on the blockchain as Sidetree transaction.

Operation Processor
-------------------
All document ‘processing' is deferred to resolution time. Resolution of the given ID to its document is done by iterating over all operations in blockchain-time order (starts with ‘create’). Each operation is checked for validity before we apply JSON patch to document.

Document Handler
----------------
Document handler performs document operation processing and document resolution. It supports both DID documents and generic documents.

**Operation Processing**

Upon successful validation against configured validator an operation will be added to the batch.

**Resolution**

Document resolution is based on ID or initial state values.

-- DID : The latest document will be returned if found.

-- Long Form DID can be requested in the following format:
    did:METHOD:<unique-portion>:Base64url(JCS({suffix-data, delta}))
