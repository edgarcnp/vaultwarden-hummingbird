//! Shared fake-S3 fixtures: request-path parsing and an empty listing.
//! The route-based (sync) and stateful (backup) stubs remain specialized;
//! these are the pieces both need byte-for-byte.

/// The request path of a logged request line, query string stripped.
pub(crate) fn req_path(line: &str) -> &str {
    line.split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

/// An empty ListObjectsV2 page, as a provider would answer it.
pub(crate) fn empty_listing() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
      <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
      <Name>vw</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
      <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
        .to_vec()
}
