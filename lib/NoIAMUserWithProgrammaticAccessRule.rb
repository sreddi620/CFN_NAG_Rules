require 'cfn-nag/violation'
require 'cfn-nag/custom_rules/base'

class NoIAMUserWithProgrammaticAccessRule < BaseRule

  def rule_text
    'User should not be provided a Programmatic access'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'WU3'
  end

  def audit_impl(cfn_model)
    violating_access_keys = cfn_model.resources_by_type('AWS::IAM::AccessKey')
    violating_access_keys.map(&:logical_resource_id)
  end
end
