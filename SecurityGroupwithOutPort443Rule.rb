# frozen_string_literal: true

require 'cfn-nag/violation'
require_relative 'base'

class SecurityGroupwithOutPort443Rule < BaseRule
  def rule_text
    'Security Groups found ingress without port 443'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'WU2'
  end

  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_ingresses = security_group.ingresses.select do |ingress|
        ingress.toPort.to_s != 443
      end

      !violating_ingresses.empty?
    end

    violating_ingresses = cfn_model.standalone_ingress.select do |standalone_ingress|
      standalone_ingress.toPort.to_s != 443
    end

    violating_security_groups.map(&:logical_resource_id) + violating_ingresses.map(&:logical_resource_id)
  end
end
