require 'cfn-nag/violation'
require_relative 'boolean_base_rule'

class NoIAMUserWithProgrammaticAccessRule < BooleanBaseRule

  def rule_text
    'User should not be provided a Programmatic access'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'WUViolation3'
  end

  def resource_type
    'AWS::IAM::AccessKey'
  end

  def boolean_property
    :AccessKey
  end
end
