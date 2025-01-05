# Qualys -> T1 Ingest Connector


This connector code will download the asset, finding, and knowledgebase metadata from
a Qualys instance, convert the data from it's native XML format into JSON, then
transform that data into the T1 spec.

All job management is handled by the pyTenable sync JobManager (currently within the 
`feature/sync` branch).  As the sync JobManager isn't yet mainlined into the pyTenable
repository, there are a few extra steps involved to setup the connector command-line
(below).

In terms of performance testing, we have observed nominal usage of memory (not much more
than 120MiB on an M1 Mac) even while streaming the Knowldgebase XML into the cache database
for later mergins with the finding data.
