# frozen_string_literal: true

require 'cfn-nag/violation'
require_relative 'base'

class SecurityGroupIngressPort22and3389Rule < BaseRule
  def rule_text
    'Security Groups found ingress with port 22 or 3389' \
    'port'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'WU_Violation_5'
  end

  ##
  # This will behave slightly different than the legacy jq based rule which was
  # targeted against inline ingress only
  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_ingresses = security_group.ingresses.select do |ingress|
        ingress.toPort = 22
      end

      !violating_ingresses.empty?
    end

    violating_ingresses = cfn_model.standalone_ingress.select do |standalone_ingress|
      standalone_ingress.toPort = 22
    end

    violating_security_groups.map(&:logical_resource_id) + violating_ingresses.map(&:logical_resource_id)
  end
end
