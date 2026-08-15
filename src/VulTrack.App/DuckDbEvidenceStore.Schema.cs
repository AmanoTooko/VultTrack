using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    private static void RecreateAffectedComponentsTable(DuckDBConnection connection)
    {
        Execute(connection, "drop table if exists affected_components");
        Execute(connection, AffectedComponentsTableStatement);
    }

    private static readonly string[] RecordEvidenceTables =
    [
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses"
    ];

    private static readonly string[] ResetTables =
    [
        "vulnerability_identifiers",
        "vulnerability_search_tokens",
        "vulnerability_latest",
        "vulnerabilities",
        "source_record_identifiers",
        "source_record_relations",
        "source_records",
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses",
        "cpe_entries",
        "exploits",
        "threat_scores",
        "sbom_matches",
        "sbom_components",
        "sbom_uploads"
    ];

    // Run before all schema DML during initialization. DuckDB 1.5.x can persist corrupted ART
    // state after incremental UPDATE/DELETE workloads. VulTrack has no PK/UNIQUE constraints,
    // so removing the old explicit indexes eliminates that mutation path.
    private static readonly string[] LegacyArtIndexDropStatements =
    [
        "drop index if exists ix_duck_affected_facts_vulnerability_key",
        "drop index if exists ix_duck_source_records_key",
        "drop index if exists ix_duck_vulnerabilities_primary",
        "drop index if exists ix_duck_vulnerabilities_id",
        "drop index if exists ix_duck_vulnerability_identifiers_value",
        "drop index if exists ix_duck_vulnerability_search_tokens_token",
        "drop index if exists ix_duck_source_record_relations_vulnerability_id",
        "drop index if exists ix_duck_source_record_relations_related_identifier",
        "drop index if exists ix_duck_ai_vulnerability",
        "drop index if exists ix_duck_severity_scores_vulnerability_key",
        "drop index if exists ix_duck_evidence_references_vulnerability_key",
        "drop index if exists ix_duck_weaknesses_vulnerability_key",
        "drop index if exists ix_duck_threat_scores_vulnerability_key",
        "drop index if exists ix_duck_affected_components_vulnerability_id",
        "drop index if exists ix_duck_affected_components_cpe",
        "drop index if exists ix_duck_affected_components_purl",
        "drop index if exists ix_duck_affected_components_purl_without_version",
        "drop index if exists ix_duck_affected_components_package_lower",
        "drop index if exists ix_duck_affected_components_display_lower",
        "drop index if exists ix_duck_sbom_components_sbom",
        "drop index if exists ix_duck_sbom_matches_sbom"
    ];

    private static readonly string[] SchemaStatements =
    [
        """
        create table if not exists source_records (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          title varchar,
          description varchar,
          status varchar,
          published_at varchar,
          modified_at varchar,
          source_url varchar,
          record_hash varchar,
          normalizer_version varchar
        )
        """,
        "alter table source_records add column if not exists normalizer_version varchar",
        """
        create table if not exists source_record_identifiers (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          identifier varchar
        )
        """,
        """
        create table if not exists source_record_relations (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          relation_type varchar,
          related_identifier varchar
        )
        """,
        """
        create table if not exists vulnerabilities (
          id varchar,
          primary_identifier varchar,
          title varchar,
          description varchar,
          status varchar,
          published_at varchar,
          modified_at varchar,
          max_cvss_score double,
          severity_label varchar,
          affected_component_count bigint,
          affected_component_names_json varchar,
          identifiers_json varchar,
          source_count bigint,
          updated_at timestamp
        )
        """,
        """
        create table if not exists vulnerability_latest (
          id varchar,
          primary_identifier varchar,
          title varchar,
          severity_label varchar,
          max_cvss_score double,
          affected_component_count bigint,
          affected_component_names_json varchar,
          published_at varchar,
          modified_at varchar
        )
        """,
        """
        insert into vulnerability_latest
        select id, primary_identifier, title, severity_label, max_cvss_score,
               affected_component_count, affected_component_names_json,
               published_at, modified_at
        from vulnerabilities
        where not exists (select 1 from vulnerability_latest limit 1)
        order by modified_at desc nulls last, primary_identifier desc
        limit 5000
        """,
        """
        create table if not exists vulnerability_identifiers (
          identifier varchar,
          vulnerability_id varchar,
          vulnerability_key varchar
        )
        """,
        """
        create table if not exists vulnerability_search_tokens (
          vulnerability_id varchar,
          token varchar
        )
        """,
        """
        create table if not exists ai_vulnerability_analyses (
          vulnerability_id varchar,
          primary_identifier varchar,
          model varchar,
          prompt_version varchar,
          evidence_hash varchar,
          analysis_json varchar,
          input_json varchar,
          input_chars integer,
          output_chars integer,
          source_url varchar,
          created_at varchar,
          updated_at varchar,
          usage_json varchar,
          prompt_tokens bigint,
          completion_tokens bigint,
          total_tokens bigint,
          cached_tokens bigint
        )
        """,
        """
        create table if not exists affected_facts (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          fact_type varchar,
          ecosystem varchar,
          package_name varchar,
          normalized_package_name varchar,
          purl varchar,
          purl_without_version varchar,
          cpe23_uri varchar,
          version_range_raw varchar,
          range_type varchar,
          vulnerable boolean
        )
        """,
        AffectedComponentsTableStatement,
        """
        create table if not exists severity_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          scoring_system varchar,
          scoring_version varchar,
          score_type varchar,
          vector_string varchar,
          score double,
          severity_label varchar
        )
        """,
        """
        create table if not exists evidence_references (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          url varchar,
          normalized_url varchar,
          ref_type varchar,
          tags_json varchar
        )
        """,
        """
        create table if not exists weaknesses (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          weakness_type varchar,
          weakness_id varchar,
          description varchar
        )
        """,
        """
        create table if not exists cpe_entries (
          source_code varchar,
          raw_index_id varchar,
          cpe23_uri varchar,
          vendor varchar,
          product varchar,
          version varchar,
          part varchar,
          target_sw varchar,
          deprecated boolean
        )
        """,
        """
        create table if not exists exploits (
          source_code varchar,
          raw_index_id varchar,
          source_key varchar,
          identifiers varchar,
          title varchar,
          source_url varchar,
          artifact_type varchar,
          exploit_type varchar,
          maturity varchar,
          verification_status varchar,
          published_at varchar,
          modified_at varchar,
          snapshot_id varchar,
          is_active boolean default true
        )
        """,
        """
        alter table exploits add column if not exists snapshot_id varchar
        """,
        """
        alter table exploits add column if not exists is_active boolean default true
        """,
        """
        create table if not exists threat_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          score_type varchar,
          score double,
          percentile double,
          observed_at varchar
        )
        """,
        """
        create table if not exists sbom_uploads (
          id varchar,
          name varchar,
          format varchar,
          metadata varchar,
          component_count integer,
          matched_count integer,
          uploaded_at timestamp default current_timestamp
        )
        """,
        """
        create table if not exists sbom_components (
          id varchar,
          sbom_id varchar,
          purl varchar,
          name varchar,
          version varchar,
          ecosystem varchar,
          group_name varchar,
          vendor varchar,
          product varchar,
          cpe23_uri varchar,
          source_package_name varchar,
          source_package_version varchar,
          component_type varchar,
          metadata varchar,
          vuln_count integer
        )
        """,
        """
        create table if not exists sbom_matches (
          id varchar,
          sbom_id varchar,
          sbom_component_id varchar,
          vulnerability_id varchar,
          purl varchar,
          display_name varchar,
          ecosystem varchar,
          normalized_range varchar,
          version_matched boolean,
          match_basis varchar,
          matched_version varchar
        )
        """
    ];

    private const string AffectedComponentsTableStatement = """
        create table if not exists affected_components (
          id varchar,
          vulnerability_id varchar,
          component_id varchar,
          ecosystem varchar,
          ecosystem_lower varchar,
          package_name varchar,
          package_name_lower varchar,
          display_name varchar,
          display_name_lower varchar,
          primary_purl varchar,
          purl_without_version varchar,
          primary_cpe23_uri varchar,
          normalized_range varchar,
          range_type varchar,
          confidence double,
          evidence_count integer,
          resolution_status varchar
        )
        """;

    private static readonly string[] AffectedComponentIndexStatements = [];

    private static readonly string[] AffectedComponentDropIndexStatements =
    [
        "drop index if exists ix_duck_affected_components_vulnerability_id",
        "drop index if exists ix_duck_affected_components_cpe",
        "drop index if exists ix_duck_affected_components_purl",
        "drop index if exists ix_duck_affected_components_purl_without_version",
        "drop index if exists ix_duck_affected_components_package_lower",
        "drop index if exists ix_duck_affected_components_display_lower"
    ];

    private static readonly string[] CatalogIndexStatements = [];

    private static readonly string[] CatalogDropIndexStatements =
    [
        "drop index if exists ix_duck_vulnerabilities_primary",
        "drop index if exists ix_duck_vulnerabilities_id",
        "drop index if exists ix_duck_vulnerability_identifiers_value",
        "drop index if exists ix_duck_vulnerability_search_tokens_token"
    ];
}
