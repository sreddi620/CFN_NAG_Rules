# frozen_string_literal: true

require 'cfn-nag/violation'
require_relative 'base'

class SecurityGroupEgresswithOutPort443Rule < BaseRule
  def rule_text
    'Security Groups found egress with other port instead of port 443'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'WU6'
  end

  ##
  # This will behave slightly different than the legacy jq based rule which was
  # targeted against inline ingress only
  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_egresses = security_group.egresses.select do |egress|
        egress.toPort.to_s != 443
      end

      !violating_egresses.empty?
    end

    violating_egresses = cfn_model.standalone_egress.select do |standalone_egress|
      standalone_egress.toPort.to_s != 443
    end

    violating_security_groups.map(&:logical_resource_id) + violating_egresses.map(&:logical_resource_id)
  end
end