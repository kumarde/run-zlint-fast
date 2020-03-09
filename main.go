package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2"
	"github.com/zmap/zlint/v2/lint"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

func LintStatusToInt(status lint.LintStatus) string {
	if status == lint.Error {
		return "1"
	} else if status == lint.Warn {
		return "2"
	} else if status == lint.Fatal {
		return "3"
	} else if status == lint.Pass {
		return "4"
	} else {
		return "5"
	}
}

var ( // flags
	listLintsJSON   bool
	listLintSources bool
	prettyprint     bool
	format          string
	nameFilter      string
	includeNames    string
	excludeNames    string
	includeSources  string
	excludeSources  string
	dataDir         string
	outFile			string

	// version is replaced by GoReleaser using an LDFlags option at release time.
	version = "dev"
)

func msToTime(ms string) (time.Time, error) {
	msInt, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	return time.Unix(0, msInt*int64(time.Millisecond)), nil
}

var LINTS = []string{
	"e_ian_wildcard_not_first",
	"e_mp_modulus_must_be_divisible_by_8",
	"e_qcstatem_qcsscd_valid",
	"e_sub_cert_country_name_must_appear",
	"e_sub_cert_eku_server_auth_client_auth_missing",
	"e_ev_country_name_missing",
	"e_ext_cert_policy_duplicate",
	"e_ext_cert_policy_explicit_text_ia5_string",
	"w_dnsname_wildcard_left_of_public_suffix",
	"w_rsa_mod_factors_smaller_than_752",
	"e_ext_ian_space_dns_name",
	"e_generalized_time_not_in_zulu",
	"e_path_len_constraint_zero_or_less",
	"e_name_constraint_empty",
	"e_ext_ian_uri_relative",
	"e_ext_san_contains_reserved_ip",
	"e_ext_san_rfc822_format_invalid",
	"e_qcstatem_qclimitvalue_valid",
	"e_subject_organization_name_max_length",
	"n_subject_common_name_included",
	"w_ext_aia_access_location_missing",
	"e_ev_business_category_missing",
	"e_issuer_dn_country_not_printable_string",
	"e_name_constraint_minimum_non_zero",
	"e_sub_cert_province_must_not_appear",
	"e_ca_country_name_invalid",
	"e_ext_san_no_entries",
	"e_san_dns_name_starts_with_period",
	"w_name_constraint_on_x400",
	"e_cert_policy_iv_requires_province_or_locality",
	"e_dsa_improper_modulus_or_divisor_size",
	"e_old_sub_ca_rsa_mod_less_than_1024_bits",
	"e_sub_cert_key_usage_crl_sign_bit_set",
	"e_sub_cert_not_is_ca",
	"w_qcstatem_qctype_web",
	"e_dnsname_wildcard_only_in_left_label",
	"e_ext_ian_uri_host_not_fqdn_or_ip",
	"e_ext_san_uri_relative",
	"e_sub_cert_aia_missing",
	"e_wrong_time_format_pre2050",
	"w_sub_ca_certificate_policies_marked_critical",
	"e_ca_common_name_missing",
	"e_ca_key_cert_sign_not_set",
	"e_ca_subject_field_empty",
	"e_sub_cert_aia_marked_critical",
	"e_subject_locality_name_max_length",
	"e_cert_unique_identifier_version_not_2_or_3",
	"e_generalized_time_includes_fraction_seconds",
	"e_issuer_field_empty",
	"e_generalized_time_does_not_include_seconds",
	"e_subject_common_name_not_from_san",
	"e_sub_cert_aia_does_not_contain_ocsp_url",
	"e_subject_dn_country_not_printable_string",
	"e_ext_cert_policy_explicit_text_too_long",
	"e_ian_dns_name_starts_with_period",
	"e_spki_rsa_encryption_parameter_not_null",
	"e_sub_cert_postal_code_must_not_appear",
	"e_subject_printable_string_badalpha",
	"e_utc_time_not_in_zulu",
	"e_cab_dv_conflicts_with_org",
	"e_ext_policy_constraints_not_critical",
	"e_sub_cert_crl_distribution_points_marked_critical",
	"e_dnsname_left_label_wildcard_correct",
	"w_ext_cert_policy_explicit_text_not_nfc",
	"w_sub_ca_aia_does_not_contain_issuing_ca_url",
	"e_sub_ca_crl_distribution_points_does_not_contain_url",
	"w_multiple_issuer_rdn",
	"w_rsa_public_exponent_not_in_range",
	"e_cab_dv_conflicts_with_street",
	"e_subject_given_name_max_length",
	"w_ext_policy_map_not_critical",
	"e_sub_cert_province_must_appear",
	"n_sub_ca_eku_not_technically_constrained",
	"w_ext_cert_policy_explicit_text_includes_control",
	"e_ext_san_uri_format_invalid",
	"e_mp_rsassa-pss_in_spki",
	"w_subject_dn_trailing_whitespace",
	"e_ext_san_dns_name_too_long",
	"e_utc_time_does_not_include_seconds",
	"w_ian_iana_pub_suffix_empty",
	"w_dnsname_underscore_in_trd",
	"e_ev_organization_name_missing",
	"e_ext_ian_no_entries",
	"e_ext_san_directory_name_present",
	"e_mp_exponent_cannot_be_one",
	"w_rsa_mod_not_odd",
	"e_ext_san_uniform_resource_identifier_present",
	"e_san_dns_name_onion_not_ev_cert",
	"w_ext_ian_critical",
	"e_ext_aia_marked_critical",
	"e_ext_cert_policy_disallowed_any_policy_qualifier",
	"e_ext_key_usage_without_bits",
	"e_path_len_constraint_improperly_included",
	"e_sub_cert_key_usage_cert_sign_bit_set",
	"e_qcstatem_qctype_valid",
	"e_root_ca_key_usage_must_be_critical",
	"e_ext_ian_rfc822_format_invalid",
	"e_rsa_exp_negative",
	"e_sub_ca_certificate_policies_missing",
	"e_cert_contains_unique_identifier",
	"e_cert_extensions_version_not_3",
	"e_dnsname_hyphen_in_sld",
	"e_name_constraint_maximum_not_absent",
	"e_qcstatem_mandatory_etsi_statems",
	"e_sub_ca_aia_does_not_contain_ocsp_url",
	"e_sub_cert_locality_name_must_not_appear",
	"e_sub_cert_street_address_should_not_exist",
	"e_dnsname_empty_label",
	"e_ext_ian_empty_name",
	"e_ext_ian_uri_format_invalid",
	"w_ext_crl_distribution_marked_critical",
	"w_name_constraint_on_edi_party_name",
	"e_ext_subject_key_identifier_missing_ca",
	"e_onion_subject_validity_time_too_large",
	"e_qcstatem_etsi_type_as_statem",
	"e_sub_cert_eku_missing",
	"w_subject_dn_leading_whitespace",
	"e_distribution_point_incomplete",
	"e_ext_san_empty_name",
	"e_ext_san_not_critical_without_subject",
	"e_subject_country_not_iso",
	"e_tbs_signature_rsa_encryption_parameter_not_null",
	"n_san_dns_name_duplicate",
	"w_eku_critical_improperly",
	"e_ext_key_usage_cert_sign_without_ca",
	"e_qcstatem_qcpds_valid",
	"e_subject_common_name_max_length",
	"e_ext_san_missing",
	"e_rsa_public_exponent_too_small",
	"e_sub_ca_crl_distribution_points_missing",
	"e_sub_ca_aia_missing",
	"e_subject_empty_without_san",
	"e_subject_postal_code_max_length",
	"e_subject_surname_max_length",
	"n_sub_ca_eku_missing",
	"e_ext_name_constraints_not_in_ca",
	"e_inhibit_any_policy_not_critical",
	"e_mp_authority_key_identifier_correct",
	"w_sub_cert_sha1_expiration_too_long",
	"e_root_ca_extended_key_usage_present",
	"e_subject_street_address_max_length",
	"w_sub_cert_aia_does_not_contain_issuing_ca_url",
	"e_dsa_correct_order_in_subgroup",
	"e_ec_improper_curves",
	"e_ext_policy_map_any_policy",
	"e_qcstatem_etsi_present_qcs_critical",
	"e_subject_organizational_unit_name_max_length",
	"n_mp_allowed_eku",
	"e_ca_key_usage_not_critical",
	"e_ian_dns_name_includes_null_char",
	"e_mp_modulus_must_be_2048_bits_or_more",
	"w_sub_ca_name_constraints_not_critical",
	"e_basic_constraints_not_critical",
	"e_san_dns_name_includes_null_char",
	"w_ext_cert_policy_explicit_text_not_utf8",
	"e_ext_tor_service_descriptor_hash_invalid",
	"e_rsa_mod_less_than_2048_bits",
	"e_qcstatem_qcretentionperiod_valid",
	"e_rsa_public_exponent_not_odd",
	"w_name_constraint_on_registered_id",
	"w_sub_ca_eku_critical",
	"e_dnsname_not_valid_tld",
	"e_ext_authority_key_identifier_no_key_identifier",
	"e_ext_subject_key_identifier_critical",
	"e_ev_valid_time_too_long",
	"e_ext_san_dns_not_ia5_string",
	"w_sub_cert_eku_extra_values",
	"e_ca_key_usage_missing",
	"e_ca_organization_name_missing",
	"e_cert_policy_iv_requires_country",
	"e_ext_san_other_name_present",
	"w_ext_subject_key_identifier_missing_sub_cert",
	"e_ext_san_registered_id_present",
	"e_sub_cert_given_name_surname_contains_correct_policy",
	"w_ext_cert_policy_contains_noticeref",
	"e_cab_dv_conflicts_with_postal",
	"e_ext_san_edi_party_name_present",
	"e_cab_ov_requires_org",
	"e_subject_contains_reserved_arpa_ip",
	"n_multiple_subject_rdn",
	"e_ext_name_constraints_not_critical",
	"e_invalid_certificate_version",
	"e_sub_cert_locality_name_must_appear",
	"e_subject_contains_reserved_ip",
	"w_ext_policy_map_not_in_cert_policy",
	"e_sub_cert_certificate_policies_missing",
	"w_ext_san_critical_with_subject_dn",
	"e_dnsname_contains_bare_iana_suffix",
	"e_dnsname_underscore_in_sld",
	"e_qcstatem_qccompliance_valid",
	"e_ev_serial_number_missing",
	"e_subject_dn_serial_number_max_length",
	"w_subject_contains_malformed_arpa_ip",
	"e_international_dns_name_not_unicode",
	"e_subject_not_dn",
	"w_issuer_dn_leading_whitespace",
	"n_ecdsa_ee_invalid_ku",
	"w_issuer_dn_trailing_whitespace",
	"e_cab_iv_requires_personal_name",
	"e_sub_cert_cert_policy_empty",
	"e_sub_cert_crl_distribution_points_does_not_contain_url",
	"w_root_ca_basic_constraints_path_len_constraint_field_present",
	"e_cert_policy_ov_requires_country",
	"e_ext_san_space_dns_name",
	"n_ca_digital_signature_not_set",
	"e_sub_cert_valid_time_longer_than_39_months",
	"e_dsa_shorter_than_2048_bits",
	"e_ext_duplicate_extension",
	"e_old_root_ca_rsa_mod_less_than_2048_bits",
	"e_ext_san_rfc822_name_present",
	"e_rsa_no_public_key",
	"e_ca_is_ca",
	"e_cab_dv_conflicts_with_province",
	"e_dsa_params_missing",
	"e_subject_dn_not_printable_characters",
	"e_subject_email_max_length",
	"e_subject_state_name_max_length",
	"w_ext_key_usage_not_critical",
	"e_ext_ian_uri_not_ia5",
	"e_ext_policy_constraints_empty",
	"e_ext_san_uri_not_ia5",
	"e_serial_number_longer_than_20_octets",
	"w_san_iana_pub_suffix_empty",
	"e_dnsname_label_too_long",
	"e_ext_san_uri_host_not_fqdn_or_ip",
	"e_public_key_type_not_allowed",
	"w_distribution_point_missing_ldap_or_uri",
	"w_extra_subject_common_names",
	"w_root_ca_contains_cert_policy",
	"e_dnsname_bad_character_in_label",
	"e_sub_cert_or_sub_ca_using_sha1",
	"e_subject_info_access_marked_critical",
	"e_sub_ca_aia_marked_critical",
	"e_ca_country_name_missing",
	"e_ext_ian_dns_not_ia5_string",
	"e_san_wildcard_not_first",
	"e_signature_algorithm_not_supported",
	"e_sub_cert_valid_time_longer_than_825_days",
	"w_ct_sct_policy_count_unsatisfied",
	"e_cab_dv_conflicts_with_locality",
	"e_old_sub_cert_rsa_mod_less_than_1024_bits",
	"e_san_bare_wildcard",
	"e_cert_policy_ov_requires_province_or_locality",
	"e_international_dns_name_not_nfc",
	"e_root_ca_key_usage_present",
	"e_ext_authority_key_identifier_missing",
	"e_ext_subject_directory_attr_critical",
	"e_validity_time_not_positive",
	"w_sub_cert_certificate_policies_marked_critical",
	"e_sub_ca_crl_distribution_points_marked_critical",
	"w_qcstatem_qcpds_lang_case",
	"e_ext_authority_key_identifier_critical",
	"e_ian_bare_wildcard",
	"e_serial_number_not_positive",
	"e_ca_crl_sign_not_set",
	"e_subject_contains_noninformational_value",
	"n_contains_redacted_dnsname",
	"e_dsa_unique_correct_representation",
	"e_ext_freshest_crl_marked_critical",
	"e_subject_dn_serial_number_not_printable_string",
}

func init() {
	flag.StringVar(&dataDir, "data-dir", "/data2/nsrg/ct/deduped_certs_2020-01-01/", "Data directory")
	flag.StringVar(&outFile, "outFile", "outfile.csv", "Outfile")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ZLint version %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] file...\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetLevel(log.InfoLevel)
}

func worker(in <-chan []string, out chan <- []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for line := range in {
		earliestCT := line[5]
		t, err := msToTime(earliestCT)
		if err != nil {
			log.Fatal("could not parse timestamp")
		}
		if t.Year() == 2019 {
			asn1Data, err := base64.StdEncoding.DecodeString(line[1])
			if err != nil {
				log.Fatal("unable to parse base64: %s", err)
			}
			c, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				log.Fatal("unable to parse certificate")
			}
			lintResult := zlint.LintCertificate(c)
			var outStr []string

			outStr = append(outStr, c.NotBefore.String())
			outStr = append(outStr, strconv.FormatBool(lintResult.ErrorsPresent))
			outStr = append(outStr, strconv.FormatBool(lintResult.WarningsPresent))
			outStr = append(outStr, strconv.FormatBool(lintResult.FatalsPresent))

			var lintResults []string
			for _, lint := range LINTS {
				lintResults = append(lintResults, LintStatusToInt(lintResult.Results[lint].Status))
			}
			joinedResults := strings.Join(lintResults, "|")
			outStr = append(outStr, joinedResults)

			out <- outStr
		}
	}
}

func reader(files []os.FileInfo, dataDir string, out chan<- []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for _, file := range files {
		filePath := filepath.Join(dataDir, file.Name())
		inFile, err := os.Open(filePath)
		if err != nil {
			log.Fatal("could not open filename: ", err)
		}

		csvReader := csv.NewReader(inFile)
		records, err := csvReader.ReadAll()
		if err != nil {
			log.Error("could not parse CSV: ", err)
		}
		for _, line := range records {
			out <- line
		}
		inFile.Close()
	}
}

func writer(in chan []string, filePath string, wg *sync.WaitGroup) {
	defer wg.Done()
	outFile, err := os.Create(filePath)
	if err != nil {
		log.Fatal("could not open outfile.")
	}

	header := []string{
		"notBefore",
		"errorsPresent",
		"warningsPresent",
		"fatalsPresent",
	}

	lintJoined := strings.Join(LINTS, "|")
	header = append(header, lintJoined)

	writer := csv.NewWriter(outFile)

	writer.Write(header)
	writer.Flush()

	defer writer.Flush()

	for data := range in {
		writer.Write(data)
	}
}

func main() {
	files, err := ioutil.ReadDir(dataDir)
	if err != nil {
		log.Fatal(err)
	}

	lineChannel := make(chan []string, 1000000)
	outChannel := make(chan []string, 1000000)
	readerWg := sync.WaitGroup{}
	workerWg := sync.WaitGroup{}
	writerWg := sync.WaitGroup{}

	readerWg.Add(1)
	go reader(files, dataDir, lineChannel, &readerWg)

	for i := 0; i < runtime.NumCPU(); i++ {
		workerWg.Add(1)
		go worker(lineChannel, outChannel, &workerWg)
	}

	writerWg.Add(1)
	go writer(outChannel, outFile, &writerWg)

	readerWg.Wait()
	close(lineChannel)
	workerWg.Wait()
	close(outChannel)
	writerWg.Wait()
}