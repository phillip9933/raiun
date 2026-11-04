use super::*;

fn xml(etag: &str, size: &str, file_id: &str) -> String {
    format!(
        "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:response><d:href>/dav/file.txt</d:href><d:propstat><d:prop><d:getetag>{etag}</d:getetag><d:getcontentlength>{size}</d:getcontentlength><oc:fileid>{file_id}</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
    )
}

fn parse(xml: &str) -> Result<Vec<RemoteEntry>, CloudError> {
    let mut entries = Vec::new();
    parse_multistatus(
        xml.as_bytes(),
        &Url::parse("https://cloud.example/dav/").unwrap(),
        "/",
        &mut |entry| {
            entries.push(entry);
            Ok(())
        },
    )?;
    Ok(entries)
}

#[test]
fn predefined_and_numeric_entities_preserve_exact_opaque_metadata() {
    for etag in [
        "&quot;a&amp;b&lt;c&gt;d&apos;e&quot;",
        "&#34;a&amp;b&lt;c&gt;d&apos;e&#34;",
        "&#x22;a&amp;b&lt;c&gt;d&apos;e&#x22;",
    ] {
        let entries = parse(&xml(etag, "&#49;&#55;", "id&amp;123")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].etag, "\"a&b<c>d'e\"");
        assert!(is_strong_etag(&entries[0].etag));
        assert_eq!(entries[0].size, 17);
        assert_eq!(entries[0].id, "id&123");
    }
}

#[test]
fn text_fragments_are_joined_before_trimming_or_parsing() {
    let entries = parse(&xml(
        "  &quot;a &amp; b&quot;  ",
        "1<!--split-->7",
        "  id&amp; 123  ",
    ))
    .unwrap();
    assert_eq!(entries[0].etag, "\"a & b\"");
    assert_eq!(entries[0].size, 17);
    assert_eq!(entries[0].id, "id& 123");
    assert_eq!(
        parse(&xml("<![CDATA[\"a&]]>b\"", "17", "id")).unwrap()[0].etag,
        "\"a&b\""
    );
    assert_eq!(
        parse(&xml("\"literal\"", "17", "id")).unwrap()[0].etag,
        "\"literal\""
    );
}

#[test]
fn unknown_and_invalid_references_fail_closed() {
    for reference in [
        "&custom;",
        "&AMP;",
        "&#0;",
        "&#x1;",
        "&#xD800;",
        "&#x110000;",
        "&#xFFFF;",
    ] {
        assert!(
            parse(&xml(&format!("\"before{reference}after\""), "1", "id")).is_err(),
            "{reference}"
        );
    }
    let body = xml("\"etag\"", "1", "id");
    assert!(parse(&format!("&custom;{body}")).is_err());
    assert!(parse(&format!("<!DOCTYPE d:multistatus [<!ENTITY custom SYSTEM 'https://unrelated.invalid/private'>]>{body}")).is_err());
}

#[test]
fn aggregate_text_bound_applies_across_entity_fragments() {
    let fragment = "a".repeat(MAX_DAV_ENTRY / 2 + 1);
    assert!(parse(&xml(&format!("{fragment}&amp;{fragment}"), "1", "id")).is_err());
}
