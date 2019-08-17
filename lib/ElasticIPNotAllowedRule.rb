require 'cfn-nag/violation'
require 'cfn-nag/custom_rules/base'

class ElasticIPNotAllowedRule < BaseRule

  def rule_text
    'Elastic IP should not be assigned'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'WU1'
  end

  def audit_impl(cfn_model)
    violating_eips = cfn_model.resources_by_type('AWS::EC2::EIP')
    violating_eip_associations = cfn_model.resources_by_type('AWS::EC2::EIPAssociation')

    (violating_eips + violating_eip_associations).map(&:logical_resource_id)
  end
end
