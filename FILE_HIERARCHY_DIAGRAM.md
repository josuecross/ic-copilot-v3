# Project File Hierarchy Map (Filtered)

Generated on: 2026-05-24

Excluded: .venv, .git internals, .ic_copilot runtime artifacts, caches, logs, __pycache__, *.pyc, .DS_Store

```text
|-- .
|-- .env
|-- .env.example
|-- .gitignore
|-- AGENTS.md
|-- ARCHITECTURE_AND_STRUCTURE_FOR_CHATGPT.md
|-- FILE_HIERARCHY_DIAGRAM.md
|-- README.md
|-- data
||--    calibration
||--    |   catalog_overlay.example.yaml
||--    |   catalog_overlay.reviewed.example.yaml
||--    |   command_registry_overlay.example.yaml
||--    |   command_registry_overlay.reviewed.example.yaml
||--    contract
||--    |   adversarial
||--    |   |   incidents
||--    |   |   |   01_url_domain_customer.txt
||--    |   |   |   02_url_path_tenant.txt
||--    |   |   |   03_fake_person_fragments.txt
||--    |   |   |   04_bot_lifecycle_command.txt
||--    |   |   |   05_historical_memory_leakage.txt
||--    |   |   |   06_unsupported_monitoring.txt
||--    |   |   |   07_already_engaged_dba.txt
||--    |   |   |   08_generic_impact_antipattern.txt
||--    |   |   |   09_prompt_injection.txt
||--    |   |   |   10_command_injection.txt
||--    |   |   replay_cases.jsonl
||--    |   command_registry.yaml
||--    |   decision_moments.jsonl
||--    |   expected
||--    |   |   01_revpro_early_engage.current_state.json
||--    |   |   01_revpro_early_engage.ic_decision.json
||--    |   |   02_payment_stripe_codefix.current_state.json
||--    |   |   02_payment_stripe_codefix.ic_decision.json
||--    |   |   03_ocm_order_creation.current_state.json
||--    |   |   03_ocm_order_creation.ic_decision.json
||--    |   |   04_uno_revenue_mapping.current_state.json
||--    |   |   04_uno_revenue_mapping.ic_decision.json
||--    |   |   05_db_high_cpu_queue.current_state.json
||--    |   |   05_db_high_cpu_queue.ic_decision.json
||--    |   |   06_negative_fake_entities.current_state.json
||--    |   |   06_negative_fake_entities.verifier_expected.json
||--    |   |   07_stale_looped_in_question.current_state.json
||--    |   |   07_stale_looped_in_question.ic_decision.json
||--    |   |   08_monitoring_after_mitigation.current_state.json
||--    |   |   08_monitoring_after_mitigation.ic_decision.json
||--    |   incidents
||--    |   |   01_revpro_early_engage.txt
||--    |   |   02_payment_stripe_codefix.txt
||--    |   |   03_ocm_order_creation.txt
||--    |   |   04_uno_revenue_mapping.txt
||--    |   |   05_db_high_cpu_queue.txt
||--    |   |   06_negative_fake_entities.txt
||--    |   |   07_stale_looped_in_question.txt
||--    |   |   08_monitoring_after_mitigation.txt
||--    |   replay_cases.jsonl
||--    |   service_catalog.yaml
||--    corpus
||--    |   default_manifest.yaml
||--    |   templates
||--    |   |   phase1_10_templates.yaml
||--    generated
||--    |   incidents
||--    |   |   synthetic_active_mitigation_no_signal_012.txt
||--    |   |   synthetic_active_mitigation_no_signal_024.txt
||--    |   |   synthetic_active_mitigation_no_signal_036.txt
||--    |   |   synthetic_active_mitigation_no_signal_042.txt
||--    |   |   synthetic_active_mitigation_no_signal_048.txt
||--    |   |   synthetic_active_mitigation_no_signal_054.txt
||--    |   |   synthetic_active_mitigation_no_signal_060.txt
||--    |   |   synthetic_active_mitigation_no_signal_066.txt
||--    |   |   synthetic_active_mitigation_no_signal_072.txt
||--    |   |   synthetic_active_mitigation_no_signal_078.txt
||--    |   |   synthetic_active_mitigation_no_signal_084.txt
||--    |   |   synthetic_active_mitigation_no_signal_090.txt
||--    |   |   synthetic_active_mitigation_no_signal_096.txt
||--    |   |   synthetic_already_engaged_dba_005.txt
||--    |   |   synthetic_already_engaged_dba_017.txt
||--    |   |   synthetic_already_engaged_dba_029.txt
||--    |   |   synthetic_already_engaged_dba_035.txt
||--    |   |   synthetic_already_engaged_dba_041.txt
||--    |   |   synthetic_already_engaged_dba_047.txt
||--    |   |   synthetic_already_engaged_dba_053.txt
||--    |   |   synthetic_already_engaged_dba_059.txt
||--    |   |   synthetic_already_engaged_dba_065.txt
||--    |   |   synthetic_already_engaged_dba_071.txt
||--    |   |   synthetic_already_engaged_dba_077.txt
||--    |   |   synthetic_already_engaged_dba_083.txt
||--    |   |   synthetic_already_engaged_dba_089.txt
||--    |   |   synthetic_already_engaged_dba_095.txt
||--    |   |   synthetic_code_fix_stripe_002.txt
||--    |   |   synthetic_code_fix_stripe_014.txt
||--    |   |   synthetic_code_fix_stripe_026.txt
||--    |   |   synthetic_code_fix_stripe_032.txt
||--    |   |   synthetic_code_fix_stripe_038.txt
||--    |   |   synthetic_code_fix_stripe_044.txt
||--    |   |   synthetic_code_fix_stripe_050.txt
||--    |   |   synthetic_code_fix_stripe_056.txt
||--    |   |   synthetic_code_fix_stripe_062.txt
||--    |   |   synthetic_code_fix_stripe_068.txt
||--    |   |   synthetic_code_fix_stripe_074.txt
||--    |   |   synthetic_code_fix_stripe_080.txt
||--    |   |   synthetic_code_fix_stripe_086.txt
||--    |   |   synthetic_code_fix_stripe_092.txt
||--    |   |   synthetic_code_fix_stripe_098.txt
||--    |   |   synthetic_command_injection_010.txt
||--    |   |   synthetic_command_injection_021.txt
||--    |   |   synthetic_command_injection_022.txt
||--    |   |   synthetic_command_injection_023.txt
||--    |   |   synthetic_command_injection_024.txt
||--    |   |   synthetic_command_injection_025.txt
||--    |   |   synthetic_command_injection_026.txt
||--    |   |   synthetic_command_injection_027.txt
||--    |   |   synthetic_command_injection_028.txt
||--    |   |   synthetic_command_injection_029.txt
||--    |   |   synthetic_command_injection_030.txt
||--    |   |   synthetic_command_injection_034.txt
||--    |   |   synthetic_command_injection_040.txt
||--    |   |   synthetic_command_injection_046.txt
||--    |   |   synthetic_command_injection_052.txt
||--    |   |   synthetic_command_injection_058.txt
||--    |   |   synthetic_command_injection_064.txt
||--    |   |   synthetic_command_injection_070.txt
||--    |   |   synthetic_command_injection_076.txt
||--    |   |   synthetic_command_injection_082.txt
||--    |   |   synthetic_command_injection_088.txt
||--    |   |   synthetic_command_injection_094.txt
||--    |   |   synthetic_command_injection_100.txt
||--    |   |   synthetic_deployment_validation_ocm_003.txt
||--    |   |   synthetic_deployment_validation_ocm_015.txt
||--    |   |   synthetic_deployment_validation_ocm_027.txt
||--    |   |   synthetic_deployment_validation_ocm_033.txt
||--    |   |   synthetic_deployment_validation_ocm_039.txt
||--    |   |   synthetic_deployment_validation_ocm_045.txt
||--    |   |   synthetic_deployment_validation_ocm_051.txt
||--    |   |   synthetic_deployment_validation_ocm_057.txt
||--    |   |   synthetic_deployment_validation_ocm_063.txt
||--    |   |   synthetic_deployment_validation_ocm_069.txt
||--    |   |   synthetic_deployment_validation_ocm_075.txt
||--    |   |   synthetic_deployment_validation_ocm_081.txt
||--    |   |   synthetic_deployment_validation_ocm_087.txt
||--    |   |   synthetic_deployment_validation_ocm_093.txt
||--    |   |   synthetic_deployment_validation_ocm_099.txt
||--    |   |   synthetic_fake_url_customer_006.txt
||--    |   |   synthetic_fake_url_customer_018.txt
||--    |   |   synthetic_fake_url_customer_030.txt
||--    |   |   synthetic_fake_url_customer_036.txt
||--    |   |   synthetic_fake_url_customer_042.txt
||--    |   |   synthetic_fake_url_customer_048.txt
||--    |   |   synthetic_fake_url_customer_054.txt
||--    |   |   synthetic_fake_url_customer_060.txt
||--    |   |   synthetic_fake_url_customer_066.txt
||--    |   |   synthetic_fake_url_customer_072.txt
||--    |   |   synthetic_fake_url_customer_078.txt
||--    |   |   synthetic_fake_url_customer_084.txt
||--    |   |   synthetic_fake_url_customer_090.txt
||--    |   |   synthetic_fake_url_customer_096.txt
||--    |   |   synthetic_fake_url_tenant_007.txt
||--    |   |   synthetic_fake_url_tenant_019.txt
||--    |   |   synthetic_fake_url_tenant_031.txt
||--    |   |   synthetic_fake_url_tenant_037.txt
||--    |   |   synthetic_fake_url_tenant_043.txt
||--    |   |   synthetic_fake_url_tenant_049.txt
||--    |   |   synthetic_fake_url_tenant_055.txt
||--    |   |   synthetic_fake_url_tenant_061.txt
||--    |   |   synthetic_fake_url_tenant_067.txt
||--    |   |   synthetic_fake_url_tenant_073.txt
||--    |   |   synthetic_fake_url_tenant_079.txt
||--    |   |   synthetic_fake_url_tenant_085.txt
||--    |   |   synthetic_fake_url_tenant_091.txt
||--    |   |   synthetic_fake_url_tenant_097.txt
||--    |   |   synthetic_historical_leakage_008.txt
||--    |   |   synthetic_historical_leakage_011.txt
||--    |   |   synthetic_historical_leakage_012.txt
||--    |   |   synthetic_historical_leakage_013.txt
||--    |   |   synthetic_historical_leakage_014.txt
||--    |   |   synthetic_historical_leakage_015.txt
||--    |   |   synthetic_historical_leakage_016.txt
||--    |   |   synthetic_historical_leakage_017.txt
||--    |   |   synthetic_historical_leakage_018.txt
||--    |   |   synthetic_historical_leakage_019.txt
||--    |   |   synthetic_historical_leakage_020.txt
||--    |   |   synthetic_historical_leakage_032.txt
||--    |   |   synthetic_historical_leakage_038.txt
||--    |   |   synthetic_historical_leakage_044.txt
||--    |   |   synthetic_historical_leakage_050.txt
||--    |   |   synthetic_historical_leakage_056.txt
||--    |   |   synthetic_historical_leakage_062.txt
||--    |   |   synthetic_historical_leakage_068.txt
||--    |   |   synthetic_historical_leakage_074.txt
||--    |   |   synthetic_historical_leakage_080.txt
||--    |   |   synthetic_historical_leakage_086.txt
||--    |   |   synthetic_historical_leakage_092.txt
||--    |   |   synthetic_historical_leakage_098.txt
||--    |   |   synthetic_missing_owner_revpro_001.txt
||--    |   |   synthetic_missing_owner_revpro_002.txt
||--    |   |   synthetic_missing_owner_revpro_003.txt
||--    |   |   synthetic_missing_owner_revpro_004.txt
||--    |   |   synthetic_missing_owner_revpro_005.txt
||--    |   |   synthetic_missing_owner_revpro_006.txt
||--    |   |   synthetic_missing_owner_revpro_007.txt
||--    |   |   synthetic_missing_owner_revpro_008.txt
||--    |   |   synthetic_missing_owner_revpro_009.txt
||--    |   |   synthetic_missing_owner_revpro_010.txt
||--    |   |   synthetic_missing_owner_revpro_013.txt
||--    |   |   synthetic_missing_owner_revpro_025.txt
||--    |   |   synthetic_missing_owner_revpro_031.txt
||--    |   |   synthetic_missing_owner_revpro_037.txt
||--    |   |   synthetic_missing_owner_revpro_043.txt
||--    |   |   synthetic_missing_owner_revpro_049.txt
||--    |   |   synthetic_missing_owner_revpro_055.txt
||--    |   |   synthetic_missing_owner_revpro_061.txt
||--    |   |   synthetic_missing_owner_revpro_067.txt
||--    |   |   synthetic_missing_owner_revpro_073.txt
||--    |   |   synthetic_missing_owner_revpro_079.txt
||--    |   |   synthetic_missing_owner_revpro_085.txt
||--    |   |   synthetic_missing_owner_revpro_091.txt
||--    |   |   synthetic_missing_owner_revpro_097.txt
||--    |   |   synthetic_monitoring_after_mitigation_004.txt
||--    |   |   synthetic_monitoring_after_mitigation_016.txt
||--    |   |   synthetic_monitoring_after_mitigation_028.txt
||--    |   |   synthetic_monitoring_after_mitigation_034.txt
||--    |   |   synthetic_monitoring_after_mitigation_040.txt
||--    |   |   synthetic_monitoring_after_mitigation_046.txt
||--    |   |   synthetic_monitoring_after_mitigation_052.txt
||--    |   |   synthetic_monitoring_after_mitigation_058.txt
||--    |   |   synthetic_monitoring_after_mitigation_064.txt
||--    |   |   synthetic_monitoring_after_mitigation_070.txt
||--    |   |   synthetic_monitoring_after_mitigation_076.txt
||--    |   |   synthetic_monitoring_after_mitigation_082.txt
||--    |   |   synthetic_monitoring_after_mitigation_088.txt
||--    |   |   synthetic_monitoring_after_mitigation_094.txt
||--    |   |   synthetic_monitoring_after_mitigation_100.txt
||--    |   |   synthetic_prompt_injection_009.txt
||--    |   |   synthetic_prompt_injection_021.txt
||--    |   |   synthetic_prompt_injection_033.txt
||--    |   |   synthetic_prompt_injection_039.txt
||--    |   |   synthetic_prompt_injection_045.txt
||--    |   |   synthetic_prompt_injection_051.txt
||--    |   |   synthetic_prompt_injection_057.txt
||--    |   |   synthetic_prompt_injection_063.txt
||--    |   |   synthetic_prompt_injection_069.txt
||--    |   |   synthetic_prompt_injection_075.txt
||--    |   |   synthetic_prompt_injection_081.txt
||--    |   |   synthetic_prompt_injection_087.txt
||--    |   |   synthetic_prompt_injection_093.txt
||--    |   |   synthetic_prompt_injection_099.txt
||--    |   |   synthetic_unknown_owner_missing_impact_011.txt
||--    |   |   synthetic_unknown_owner_missing_impact_023.txt
||--    |   |   synthetic_unknown_owner_missing_impact_035.txt
||--    |   |   synthetic_unknown_owner_missing_impact_041.txt
||--    |   |   synthetic_unknown_owner_missing_impact_047.txt
||--    |   |   synthetic_unknown_owner_missing_impact_053.txt
||--    |   |   synthetic_unknown_owner_missing_impact_059.txt
||--    |   |   synthetic_unknown_owner_missing_impact_065.txt
||--    |   |   synthetic_unknown_owner_missing_impact_071.txt
||--    |   |   synthetic_unknown_owner_missing_impact_077.txt
||--    |   |   synthetic_unknown_owner_missing_impact_083.txt
||--    |   |   synthetic_unknown_owner_missing_impact_089.txt
||--    |   |   synthetic_unknown_owner_missing_impact_095.txt
||--    |   manifest.yaml
||--    |   replay_cases.jsonl
||--    prompt_variants
||--    |   phase1_10_variants.yaml
||--    review_templates
||--    |   reviewer_labels_template.jsonl
||--    sample
||--    |   decision_moments
||--    |   |   dm_code_fix_eta_blocker.yaml
||--    |   |   dm_missing_owner_after_support_signal.yaml
||--    |   |   dm_monitoring_after_mitigation.yaml
||--    |   |   dm_negative_historical_fact_leakage.yaml
||--    |   eval_cases
||--    |   |   fake_atlassian_customer.yaml
||--    |   |   fake_docs_tenant.yaml
||--    |   |   historical_fact_leakage.yaml
||--    |   |   revpro_early_engage.yaml
||--    |   |   stale_looped_in_question.yaml
||--    |   incidents
||--    |   |   ocm_order_creation.txt
||--    |   |   payment_stripe_psg.txt
||--    |   |   revpro_early_engage.txt
||--    |   |   uno_zbzr_central_sandbox.txt
||--    |   service_catalog.yaml
|-- docs
||--    ARTIFACT_CURATION_WORKFLOW.md
||--    ENTERPRISE_ARTIFACT_EXTRACTION_PROMPT.md
||--    LOCAL_WEB_CONSOLE.md
||--    PERSONAL_SHADOW_CALIBRATION.md
||--    PROMPT_VARIANT_GUIDE.md
||--    REAL_LLM_READINESS.md
||--    REVIEW_LABEL_GUIDE.md
||--    SHADOW_PROMOTION_CRITERIA.md
|-- ic_copilot.local.example.yaml
|-- ic_copilot_previous_incidents__try_20260523_193347__fixture_package
||--    IN-10978
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-10978_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-10978_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-10978_001.json
||--    |   |   |   dm_IN-10978_002.json
||--    |   |   expected
||--    |   |   |   IN-10978_current_state.json
||--    |   |   |   IN-10978_ic_decision.json
||--    |   |   |   IN-10978_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-10978.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-10978_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-10978_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-10978.json
||--    |   |   review_labels
||--    |   |   |   IN-10978_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-10978_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-10983
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-10983_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-10983_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-10983_001.json
||--    |   |   expected
||--    |   |   |   IN-10983_current_state.json
||--    |   |   |   IN-10983_ic_decision.json
||--    |   |   |   IN-10983_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-10983.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-10983_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-10983_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-10983.json
||--    |   |   review_labels
||--    |   |   |   IN-10983_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-10983_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-10984
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-10984_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-10984_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-10984_001.json
||--    |   |   expected
||--    |   |   |   IN-10984_current_state.json
||--    |   |   |   IN-10984_ic_decision.json
||--    |   |   |   IN-10984_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-10984.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-10984_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-10984_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-10984.json
||--    |   |   review_labels
||--    |   |   |   IN-10984_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-10984_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-10990
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-10990_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-10990_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-10990_001.json
||--    |   |   expected
||--    |   |   |   IN-10990_current_state.json
||--    |   |   |   IN-10990_ic_decision.json
||--    |   |   |   IN-10990_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-10990.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-10990_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-10990_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-10990.json
||--    |   |   review_labels
||--    |   |   |   IN-10990_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-10990_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-11032_fragment
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-11032_fragment_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-11032_fragment_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-11032_fragment_001.json
||--    |   |   expected
||--    |   |   |   IN-11032_fragment_current_state.json
||--    |   |   |   IN-11032_fragment_ic_decision.json
||--    |   |   |   IN-11032_fragment_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-11032_fragment.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-11032_fragment_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-11032_fragment_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-11032_fragment.json
||--    |   |   review_labels
||--    |   |   |   IN-11032_fragment_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-11032_fragment_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-11041
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-11041_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-11041_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-11041_001.json
||--    |   |   expected
||--    |   |   |   IN-11041_current_state.json
||--    |   |   |   IN-11041_ic_decision.json
||--    |   |   |   IN-11041_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-11041.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-11041_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-11041_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-11041.json
||--    |   |   review_labels
||--    |   |   |   IN-11041_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-11041_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    IN-11057
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   IN-11057_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   IN-11057_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_IN-11057_001.json
||--    |   |   expected
||--    |   |   |   IN-11057_current_state.json
||--    |   |   |   IN-11057_ic_decision.json
||--    |   |   |   IN-11057_state_delta.json
||--    |   |   incidents
||--    |   |   |   IN-11057.jsonl
||--    |   |   question_ledgers
||--    |   |   |   IN-11057_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   IN-11057_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   IN-11057.json
||--    |   |   review_labels
||--    |   |   |   IN-11057_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   IN-11057_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    MASTER_MANIFEST.txt
||--    README.md
||--    unknown_daco_long_running_queries
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   unknown_daco_long_running_queries_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   unknown_daco_long_running_queries_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_unknown_daco_long_running_queries_001.json
||--    |   |   expected
||--    |   |   |   unknown_daco_long_running_queries_current_state.json
||--    |   |   |   unknown_daco_long_running_queries_ic_decision.json
||--    |   |   |   unknown_daco_long_running_queries_state_delta.json
||--    |   |   incidents
||--    |   |   |   unknown_daco_long_running_queries.jsonl
||--    |   |   question_ledgers
||--    |   |   |   unknown_daco_long_running_queries_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   unknown_daco_long_running_queries_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   unknown_daco_long_running_queries.json
||--    |   |   review_labels
||--    |   |   |   unknown_daco_long_running_queries_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   unknown_daco_long_running_queries_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    unknown_ebs_volume_increase
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   unknown_ebs_volume_increase_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   unknown_ebs_volume_increase_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_unknown_ebs_volume_increase_001.json
||--    |   |   expected
||--    |   |   |   unknown_ebs_volume_increase_current_state.json
||--    |   |   |   unknown_ebs_volume_increase_ic_decision.json
||--    |   |   |   unknown_ebs_volume_increase_state_delta.json
||--    |   |   incidents
||--    |   |   |   unknown_ebs_volume_increase.jsonl
||--    |   |   question_ledgers
||--    |   |   |   unknown_ebs_volume_increase_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   unknown_ebs_volume_increase_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   unknown_ebs_volume_increase.json
||--    |   |   review_labels
||--    |   |   |   unknown_ebs_volume_increase_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   unknown_ebs_volume_increase_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    unknown_revpro_edition_update
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   unknown_revpro_edition_update_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   unknown_revpro_edition_update_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_unknown_revpro_edition_update_001.json
||--    |   |   expected
||--    |   |   |   unknown_revpro_edition_update_current_state.json
||--    |   |   |   unknown_revpro_edition_update_ic_decision.json
||--    |   |   |   unknown_revpro_edition_update_state_delta.json
||--    |   |   incidents
||--    |   |   |   unknown_revpro_edition_update.jsonl
||--    |   |   question_ledgers
||--    |   |   |   unknown_revpro_edition_update_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   unknown_revpro_edition_update_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   unknown_revpro_edition_update.json
||--    |   |   review_labels
||--    |   |   |   unknown_revpro_edition_update_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   unknown_revpro_edition_update_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    unknown_slack_ecm_approval
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   unknown_slack_ecm_approval_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   unknown_slack_ecm_approval_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_unknown_slack_ecm_approval_001.json
||--    |   |   expected
||--    |   |   |   unknown_slack_ecm_approval_current_state.json
||--    |   |   |   unknown_slack_ecm_approval_ic_decision.json
||--    |   |   |   unknown_slack_ecm_approval_state_delta.json
||--    |   |   incidents
||--    |   |   |   unknown_slack_ecm_approval.jsonl
||--    |   |   question_ledgers
||--    |   |   |   unknown_slack_ecm_approval_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   unknown_slack_ecm_approval_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   unknown_slack_ecm_approval.json
||--    |   |   review_labels
||--    |   |   |   unknown_slack_ecm_approval_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   unknown_slack_ecm_approval_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
||--    unknown_zdp_latency_sbx01
||--    |   calibration_summary.txt
||--    |   file_manifest.txt
||--    |   fixture_quality.yaml
||--    |   fixtures
||--    |   |   catalog_updates
||--    |   |   |   unknown_zdp_latency_sbx01_service_catalog_candidates.yaml
||--    |   |   command_updates
||--    |   |   |   unknown_zdp_latency_sbx01_command_registry_candidates.yaml
||--    |   |   decision_moments
||--    |   |   |   dm_unknown_zdp_latency_sbx01_001.json
||--    |   |   expected
||--    |   |   |   unknown_zdp_latency_sbx01_current_state.json
||--    |   |   |   unknown_zdp_latency_sbx01_ic_decision.json
||--    |   |   |   unknown_zdp_latency_sbx01_state_delta.json
||--    |   |   incidents
||--    |   |   |   unknown_zdp_latency_sbx01.jsonl
||--    |   |   question_ledgers
||--    |   |   |   unknown_zdp_latency_sbx01_question_ledger.json
||--    |   |   rejected_entities
||--    |   |   |   unknown_zdp_latency_sbx01_rejected_entities.json
||--    |   |   replay_cases
||--    |   |   |   unknown_zdp_latency_sbx01.json
||--    |   |   review_labels
||--    |   |   |   unknown_zdp_latency_sbx01_review_seed.json
||--    |   |   verifier_cases
||--    |   |   |   unknown_zdp_latency_sbx01_verifier_cases.json
||--    |   incident_metadata.yaml
||--    |   redaction_map.md
||--    |   uncertainty_do_not_invent.txt
|-- pyproject.toml
|-- scripts
||--    analyze_review_labels.py
||--    analyze_reviewer_agreement.py
||--    audit_repo_conflicts.py
||--    audit_web_console.py
||--    build_artifact_review_report.py
||--    build_calibration_overlay_draft.py
||--    build_corpus_coverage_report.py
||--    build_overlay_review_checklist.py
||--    build_personal_shadow_readiness_report.py
||--    build_previous_incident_candidate_report.py
||--    build_previous_incident_coverage_report.py
||--    build_previous_incident_remediation_plan.py
||--    build_promotion_report.py
||--    check_calibration_overlay_review.py
||--    check_previous_incident_fixture_quality.py
||--    check_product_provider.py
||--    compare_calibration_overlay_impact.py
||--    compare_previous_incident_calibration.py
||--    compare_prompt_variants.py
||--    dev
||--    |   run_fixture_pipeline.py
||--    export_previous_incident_review_queue.py
||--    export_review_queue.py
||--    export_web_feedback.py
||--    import_artifact_bundle.py
||--    import_previous_incident_artifacts.py
||--    import_private_corpus.py
||--    make_reviewer_label_batch.py
||--    make_reviewer_label_template.py
||--    promote_artifact_package.py
||--    quarantine_test_artifacts.py
||--    run_acceptance_gate.py
||--    run_generated_corpus_workflow.py
||--    run_local_web.py
||--    run_openai_live_gate.py
||--    run_openai_review_workflow.py
||--    run_openai_shadow_eval.py
||--    run_openai_shadow_smoke.py
||--    run_personal_product_trial_report.py
||--    run_personal_shadow_calibration.py
||--    run_phase19_smoke.py
||--    run_previous_incident_calibration.py
||--    run_previous_incident_package_calibration.py
||--    run_previous_incident_verifier_cases.py
||--    run_product_smoke.py
||--    run_prompt_variant_shadow_eval.py
||--    run_replay_eval.py
||--    run_reviewed_artifact_calibration.py
||--    scan_local_secrets.py
||--    validate_artifact_package.py
||--    validate_fixture_shapes.py
||--    validate_previous_incident_package.py
||--    validate_review_labels.py
|-- src
||--    ic_copilot
||--    |   __init__.py
||--    |   artifacts
||--    |   |   __init__.py
||--    |   |   diff.py
||--    |   |   export_from_run.py
||--    |   |   import_bundle.py
||--    |   |   import_previous_package.py
||--    |   |   models.py
||--    |   |   package.py
||--    |   |   promotion.py
||--    |   |   review.py
||--    |   |   review_report.py
||--    |   |   summary.py
||--    |   |   types.py
||--    |   |   validation.py
||--    |   calibration_compare.py
||--    |   calibration_failures.py
||--    |   calibration_overlay.py
||--    |   catalog.py
||--    |   cli.py
||--    |   corpus.py
||--    |   corpus_coverage.py
||--    |   corpus_generation.py
||--    |   env.py
||--    |   error_sanitizer.py
||--    |   evals.py
||--    |   extractor.py
||--    |   fallback_analysis.py
||--    |   fixture_quality.py
||--    |   incident_loader.py
||--    |   llm
||--    |   |   __init__.py
||--    |   |   base.py
||--    |   |   config.py
||--    |   |   factory.py
||--    |   |   fixture_client.py
||--    |   |   product_client.py
||--    |   |   prompts
||--    |   |   prompts.py
||--    |   |   |   memory_applicability_contract.md
||--    |   |   |   planner_contract.md
||--    |   |   |   state_extractor_contract.md
||--    |   |   |   verifier_contract.md
||--    |   |   providers
||--    |   |   |   __init__.py
||--    |   |   |   anthropic_json.py
||--    |   |   |   base_json.py
||--    |   |   |   gemini_json.py
||--    |   |   |   local_http_json.py
||--    |   |   |   openai_json.py
||--    |   |   redaction.py
||--    |   |   stub_client.py
||--    |   memory.py
||--    |   normalizers
||--    |   |   __init__.py
||--    |   |   incident_jsonl.py
||--    |   |   slack_export.py
||--    |   |   slack_paste.py
||--    |   overlay_builder.py
||--    |   overlay_impact.py
||--    |   overlay_review_checklist.py
||--    |   overlay_review_gate.py
||--    |   personal_readiness.py
||--    |   pipeline.py
||--    |   planner.py
||--    |   previous_incident_adapters.py
||--    |   previous_incident_calibration.py
||--    |   previous_incident_candidates.py
||--    |   previous_incident_coverage.py
||--    |   previous_incident_review_queue.py
||--    |   previous_incidents.py
||--    |   private_corpus.py
||--    |   product_smoke.py
||--    |   product_trial.py
||--    |   promotion_report.py
||--    |   prompt_variant_report.py
||--    |   prompt_variants.py
||--    |   prompt_versions.py
||--    |   provider_health.py
||--    |   remediation_plan.py
||--    |   render.py
||--    |   repo_audit.py
||--    |   review.py
||--    |   review_analysis.py
||--    |   review_queue.py
||--    |   reviewer_agreement.py
||--    |   runtime_config.py
||--    |   runtime_diagnostics.py
||--    |   runtime_resources.py
||--    |   schemas.py
||--    |   shadow.py
||--    |   shadow_artifacts.py
||--    |   shadow_evals.py
||--    |   state_merge.py
||--    |   storage.py
||--    |   trigger.py
||--    |   verifier.py
||--    |   web
||--    |   |   __init__.py
||--    |   |   app.py
||--    |   |   artifact_routes.py
||--    |   |   models.py
||--    |   |   pipeline_events.py
||--    |   |   run_store.py
||--    |   |   safety.py
||--    |   |   static
||--    |   |   |   app.js
||--    |   |   |   styles.css
||--    |   |   templates
||--    |   |   |   index.html
||--    ic_copilot_mvp.egg-info
||--    |   PKG-INFO
||--    |   SOURCES.txt
||--    |   dependency_links.txt
||--    |   requires.txt
||--    |   top_level.txt
|-- tests
||--    contract
||--    |   test_memory_contract.py
||--    |   test_normalizer_contract.py
||--    |   test_planner_verifier_contract.py
||--    |   test_replay_fixtures.py
||--    |   test_state_extractor_contract.py
||--    |   test_state_merger_contract.py
||--    helpers.py
||--    live
||--    |   test_openai_shadow_live.py
||--    test_architecture_invariants.py
||--    test_artifact_diff.py
||--    test_artifact_export_from_run.py
||--    test_artifact_import_bundle.py
||--    test_artifact_import_previous_package.py
||--    test_artifact_models.py
||--    test_artifact_promotion.py
||--    test_artifact_promotion_gate.py
||--    test_artifact_review_models.py
||--    test_artifact_review_report.py
||--    test_artifact_review_store.py
||--    test_artifact_store.py
||--    test_artifact_type_classification.py
||--    test_artifact_validation.py
||--    test_artifact_validation_findings.py
||--    test_calibration_compare.py
||--    test_calibration_failures.py
||--    test_calibration_overlay_package_run.py
||--    test_catalog.py
||--    test_catalog_overlay.py
||--    test_cli_shadow.py
||--    test_command_gap_classification.py
||--    test_corpus_coverage.py
||--    test_corpus_generation.py
||--    test_corpus_manifest.py
||--    test_env_loading.py
||--    test_eval_runner.py
||--    test_fallback_analysis.py
||--    test_fixture_quality_checks.py
||--    test_generated_corpus_workflow.py
||--    test_gitignore_safety.py
||--    test_incident_jsonl_normalizer.py
||--    test_incident_loader_routing_current.py
||--    test_jsonl_pipeline_invariants.py
||--    test_llm_config.py
||--    test_llm_readiness.py
||--    test_memory.py
||--    test_memory_traceability.py
||--    test_openai_json_client.py
||--    test_overlay_builder.py
||--    test_overlay_impact.py
||--    test_overlay_review_checklist.py
||--    test_overlay_review_gate.py
||--    test_personal_readiness_phase13.py
||--    test_personal_shadow_output.py
||--    test_personal_shadow_readiness_report.py
||--    test_phase110_acceptance_extensions.py
||--    test_phase114_pattern_regressions.py
||--    test_phase115_command_gap_handling.py
||--    test_phase115_planner_patterns.py
||--    test_phase115_remediation_selection.py
||--    test_phase115_repo_status.py
||--    test_phase119_repo_cleanup.py
||--    test_phase120_docs_status.py
||--    test_phase122_error_sanitizer.py
||--    test_phase122_product_smoke.py
||--    test_phase122_provider_diagnostics.py
||--    test_phase122_provider_health.py
||--    test_phase122_secret_scan.py
||--    test_phase122_web_provider_failures.py
||--    test_phase122_web_ui_cleanup.py
||--    test_phase13_previous_package_patterns.py
||--    test_phase16_adversarial.py
||--    test_phase17_invariants.py
||--    test_phase19_cli.py
||--    test_previous_incident_adapters.py
||--    test_previous_incident_calibration.py
||--    test_previous_incident_candidate_report.py
||--    test_previous_incident_candidates.py
||--    test_previous_incident_coverage.py
||--    test_previous_incident_package.py
||--    test_previous_incident_package_calibration_all_cases.py
||--    test_previous_incident_review_queue.py
||--    test_previous_incident_verifier_cases.py
||--    test_previous_incident_verifier_runner.py
||--    test_private_corpus.py
||--    test_product_llm_client.py
||--    test_product_pipeline_defaults.py
||--    test_product_runtime_config.py
||--    test_product_trial_report.py
||--    test_promotion_report.py
||--    test_prompt_variant_report.py
||--    test_prompt_variant_shadow.py
||--    test_prompt_variants.py
||--    test_prompt_versions.py
||--    test_provider_adapters_no_network.py
||--    test_redaction.py
||--    test_remediation_plan.py
||--    test_repo_audit.py
||--    test_review_analysis.py
||--    test_review_label_batch.py
||--    test_review_queue.py
||--    test_review_schema.py
||--    test_reviewed_artifact_calibration.py
||--    test_reviewer_agreement.py
||--    test_revpro_end_to_end.py
||--    test_runtime_resources.py
||--    test_shadow_artifacts.py
||--    test_shadow_eval.py
||--    test_shadow_pipeline.py
||--    test_slack_paste_normalizer.py
||--    test_state_merge.py
||--    test_trace_contract.py
||--    test_trigger.py
||--    test_verifier.py
||--    test_verifier_current_id_context.py
||--    test_web_app.py
||--    test_web_artifact_review_routes.py
||--    test_web_artifact_review_ui.py
||--    test_web_artifact_routes.py
||--    test_web_artifact_ui.py
||--    test_web_correction_drafts.py
||--    test_web_phase18_usability.py
||--    test_web_pipeline_events.py
||--    test_web_run_store.py
||--    test_web_safety.py
||--    test_web_safety_audit.py
||--    test_web_static_ui.py
```
