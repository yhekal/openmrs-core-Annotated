/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.validator;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.openmrs.Allergen;
import org.openmrs.Allergies;
import org.openmrs.Allergy;
import org.openmrs.annotation.Handler;
import org.openmrs.api.PatientService;
import org.openmrs.messagesource.MessageSourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component("allergyValidator")
@Handler(supports = { Allergy.class }, order = 50)
public class AllergyValidator implements Validator {
	
	@Autowired
	private MessageSourceService messageSourceService;
	
	@Autowired
	private PatientService patientService;
	
	@Override
	public boolean supports(Class<?> clazz) {
		return Allergy.class.isAssignableFrom(clazz);
	}
	
	/**
	 * @see Validator#validate(Object, org.springframework.validation.Errors)
	 * @param target
	 * @param errors
	 * <strong>Should</strong> fail for a null value
	 * <strong>Should</strong> fail if patient is null
	 * <strong>Should</strong> fail id allergenType is null
	 * <strong>Should</strong> fail if allergen is null
	 * <strong>Should</strong> fail if codedAllergen is null
	 * <strong>Should</strong> fail if nonCodedAllergen is null and allergen is set to other non coded
	 * <strong>Should</strong> reject a duplicate allergen
	 * <strong>Should</strong> reject a duplicate non coded allergen
	 * <strong>Should</strong> pass for a valid allergy
	 * <strong>Should</strong> reject numeric values and symbols on reactionNonCoded
	 */
	@Override
		// &begin[validate]
	public void validate(Object target, Errors errors) {
		
		if (target == null) {
			throw new IllegalArgumentException("Allergy should not be null");
		}
		
		ValidationUtils.rejectIfEmpty(errors, "patient", "allergyapi.patient.required");
		
		Allergy allergy = (Allergy) target;
		
		if (allergy.getReactionNonCoded() != null) {
			if (NumberUtils.isParsable(allergy.getReactionNonCoded())) {
				errors.rejectValue("reactionNonCoded", "error.allergyapi.allergy.ReactionNonCoded.cannotBeNumeric");
			}
		}
		if (allergy.getAllergen() == null) {
			errors.rejectValue("allergen", "allergyapi.allergen.required");
		} else {
			Allergen allergen = allergy.getAllergen();
			if (allergen.getAllergenType() == null) {
				errors.rejectValue("allergen", "allergyapi.allergenType.required");
			}
			
			if (allergen.getCodedAllergen() == null && StringUtils.isBlank(allergen.getNonCodedAllergen())) {
				errors.rejectValue("allergen", "allergyapi.allergen.codedOrNonCodedAllergen.required");
			} else if (!allergen.isCoded() && StringUtils.isBlank(allergen.getNonCodedAllergen())) {
				errors.rejectValue("allergen", "allergyapi.allergen.nonCodedAllergen.required");
			}
			
			if (allergy.getAllergyId() == null && allergy.getPatient() != null) {
				Allergies existingAllergies = patientService.getAllergies(allergy.getPatient());
				if (existingAllergies.containsAllergen(allergy)) {
					String key = "ui.i18n.Concept.name." + allergen.getCodedAllergen().getUuid();
					String name = messageSourceService.getMessage(key);
					if (key.equals(name)) {
						name = allergen.toString();
					}
					errors.rejectValue("allergen", "allergyapi.message.duplicateAllergen", new Object[] { name }, null);
				}
			}
		}
	}
	// &end[validate]
}
