from app.connectors.elastic import build_elastic_query
from app.utils.checkpoint import ElasticCheckpoint


def test_query_builder_with_checkpoint() -> None:
    checkpoint = ElasticCheckpoint(last_ts="2024-05-01T10:11:12Z")
    query = build_elastic_query(
        checkpoint.last_ts,
        max_events=500,
        start_ago_seconds=3600,
        pit_id="pit-123",
    )
    assert query["size"] == 500
    assert query["sort"] == [{"@timestamp": "asc"}, {"_shard_doc": "asc"}]
    filter_clause = query["query"]["bool"]["filter"][0]
    assert filter_clause == {"range": {"@timestamp": {"gte": "2024-05-01T10:11:12Z"}}}


def test_query_builder_without_checkpoint() -> None:
    checkpoint = ElasticCheckpoint()
    query = build_elastic_query(
        checkpoint.last_ts,
        max_events=250,
        start_ago_seconds=900,
        pit_id="pit-456",
    )
    assert query["size"] == 250
    filter_clause = query["query"]["bool"]["filter"][0]
    assert filter_clause == {"range": {"@timestamp": {"gte": "now-900s"}}}
