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

Document resolution is based on ID or encoded original document.

-- ID : The latest document will be returned if found.

-- ID with initial-state parameter: The ID is passed in along with the initial-values parameter as follows: <ID>;initial-values=<encoded-DID-document>. Standard resolution is performed if the DID is found in the document store. If the document cannot be found then the encoded DID Document is used to generate and return as the resolved DID Document, in which case the supplied encoded DID Document is subject to the same validation as an original DID Document in a create operation.
