// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_

#include <string_view>

namespace proofs {

struct MdocAttribute {
  std::string_view identifier;
  std::string_view documentspec;
};

// Extracted from
// https://github.com/ISOWG10/ISO-18013/blob/main/Working%20Documents/Working%20Draft%20WG%2010_N2549_ISO-IEC%2018013-5-%20Personal%20identification%20%E2%80%94%20ISO-compliant%20driving%20licence%20%E2%80%94%20Part%205-%20Mobile%20driving%20lic.pdf
// https://www.aamva.org/getmedia/bb4fee66-592d-4d39-813a-8fdfd910268a/MobileDLGuidelines1-5.pdf
constexpr MdocAttribute kMdocAttributes[] = {
    {"family_name", "org.iso.18013.5.1"},
    {"given_name", "org.iso.18013.5.1"},
    {"birth_date", "org.iso.18013.5.1"},
    {"issue_date", "org.iso.18013.5.1"},
    {"expiry_date", "org.iso.18013.5.1"},
    {"issuing_country", "org.iso.18013.5.1"},
    {"issuing_authority", "org.iso.18013.5.1"},
    {"document_number", "org.iso.18013.5.1"},
    {"portrait", "org.iso.18013.5.1"},
    {"driving_privileges", "org.iso.18013.5.1"},
    {"un_distinguishing_sign", "org.iso.18013.5.1"},
    {"administrative_number", "org.iso.18013.5.1"},
    {"sex", "org.iso.18013.5.1"},
    {"height", "org.iso.18013.5.1"},
    {"weight", "org.iso.18013.5.1"},
    {"eye_colour", "org.iso.18013.5.1"},
    {"hair_colour", "org.iso.18013.5.1"},
    {"birth_place", "org.iso.18013.5.1"},
    {"resident_address", "org.iso.18013.5.1"},
    {"portrait_capture_date", "org.iso.18013.5.1"},
    {"age_in_years", "org.iso.18013.5.1"},
    {"age_birth_year", "org.iso.18013.5.1"},
    {"age_over_10", "org.iso.18013.5.1"},
    {"age_over_11", "org.iso.18013.5.1"},
    {"age_over_12", "org.iso.18013.5.1"},
    {"age_over_13", "org.iso.18013.5.1"},
    {"age_over_14", "org.iso.18013.5.1"},
    {"age_over_15", "org.iso.18013.5.1"},
    {"age_over_16", "org.iso.18013.5.1"},
    {"age_over_17", "org.iso.18013.5.1"},
    {"age_over_18", "org.iso.18013.5.1"},
    {"age_over_19", "org.iso.18013.5.1"},
    {"age_over_20", "org.iso.18013.5.1"},
    {"age_over_21", "org.iso.18013.5.1"},
    {"age_over_23", "org.iso.18013.5.1"},
    {"age_over_25", "org.iso.18013.5.1"},
    {"age_over_50", "org.iso.18013.5.1"},
    {"age_over_55", "org.iso.18013.5.1"},
    {"age_over_60", "org.iso.18013.5.1"},
    {"age_over_65", "org.iso.18013.5.1"},
    {"age_over_70", "org.iso.18013.5.1"},
    {"age_over_75", "org.iso.18013.5.1"},
    {"issuing_jurisdiction", "org.iso.18013.5.1"},
    {"nationality", "org.iso.18013.5.1"},
    {"resident_city", "org.iso.18013.5.1"},
    {"resident_state", "org.iso.18013.5.1"},
    {"resident_postal_code", "org.iso.18013.5.1"},
    {"resident_country", "org.iso.18013.5.1"},
    {"biometric_template_face", "org.iso.18013.5.1"},
    {"biometric_template_voice", "org.iso.18013.5.1"},
    {"biometric_template_finger", "org.iso.18013.5.1"},
    {"biometric_template_iris", "org.iso.18013.5.1"},
    {"biometric_template_retina", "org.iso.18013.5.1"},
    {"biometric_template_hand_geometry", "org.iso.18013.5.1"},
    {"biometric_template_keystroke", "org.iso.18013.5.1"},
    {"biometric_template_signature_sign", "org.iso.18013.5.1"},
    {"biometric_template_lip_movement", "org.iso.18013.5.1"},
    {"biometric_template_thermal_face", "org.iso.18013.5.1"},
    {"biometric_template_thermal_hand", "org.iso.18013.5.1"},
    {"biometric_template_gait", "org.iso.18013.5.1"},
    {"biometric_template_body_odor", "org.iso.18013.5.1"},
    {"biometric_template_dna", "org.iso.18013.5.1"},
    {"biometric_template_ear", "org.iso.18013.5.1"},
    {"biometric_template_finger_geometry", "org.iso.18013.5.1"},
    {"biometric_template_palm_geometry", "org.iso.18013.5.1"},
    {"biometric_template_vein_pattern", "org.iso.18013.5.1"},
    {"biometric_template_foot_print", "org.iso.18013.5.1"},
    {"family_name_national_character", "org.iso.18013.5.1"},
    {"given_name_national_character", "org.iso.18013.5.1"},
    {"signature_usual_mark", "org.iso.18013.5.1"},

    {"name_suffix", "org.iso.18013.5.1.aamva"},
    {"organ_donor", "org.iso.18013.5.1.aamva"},
    {"veteran", "org.iso.18013.5.1.aamva"},
    {"family_name_truncation", "org.iso.18013.5.1.aamva"},
    {"given_name_truncation", "org.iso.18013.5.1.aamva"},
    {"aka_family_name.v2", "org.iso.18013.5.1.aamva"},
    {"aka_given_name.v2", "org.iso.18013.5.1.aamva"},
    {"aka_suffix", "org.iso.18013.5.1.aamva"},
    {"weight_range", "org.iso.18013.5.1.aamva"},
    {"race_ethnicity", "org.iso.18013.5.1.aamva"},
    {"sex", "org.iso.18013.5.1.aamva"},
    {"first_name", "org.iso.18013.5.1.aamva"},
    {"middle_names", "org.iso.18013.5.1.aamva"},
    {"first_name_truncation", "org.iso.18013.5.1.aamva"},
    {"middle_names_truncation", "org.iso.18013.5.1.aamva"},
    {"EDL_credential", "org.iso.18013.5.1.aamva"},
    {"EDL_credential.v2", "org.iso.18013.5.1.aamva"},
    {"DHS_compliance", "org.iso.18013.5.1.aamva"},
    {"resident_county", "org.iso.18013.5.1.aamva"},
    {"resident_county.v2", "org.iso.18013.5.1.aamva"},
    {"hazmat_endorsement_expiration_date", "org.iso.18013.5.1.aamva"},
    {"CDL_indicator", "org.iso.18013.5.1.aamva"},
    {"CDL_non_domiciled", "org.iso.18013.5.1.aamva"},
    {"CDL_non_domiciled.v2", "org.iso.18013.5.1.aamva"},
    {"DHS_compliance_text", "org.iso.18013.5.1.aamva"},
    {"DHS_temporary_lawful_status", "org.iso.18013.5.1.aamva"},
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_ATTRIBUTE_IDS_H_
