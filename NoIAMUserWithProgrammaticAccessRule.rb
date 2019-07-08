require 'cfn-nag/violation'
require_relative 'boolean_base_rule'

class NoIAMUserWithProgrammaticAccessRule < BooleanBaseRule

  def rule_text
    'Elastic IP should not be assigned'
  end

  def rule_type
    Violation::FAILING_VIOLATION
  end

  def rule_id
    'WU4'
  end

  def resource_type
    'AWS::IAM::AccessKey'
  end

  def boolean_property
    :AccessKey
  end
end
