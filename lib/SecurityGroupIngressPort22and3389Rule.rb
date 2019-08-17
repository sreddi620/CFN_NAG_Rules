# frozen_string_literal: true

require 'cfn-nag/violation'
require 'cfn-nag/custom_rules/base'

class SecurityGroupIngressPort22and3389Rule < BaseRule
  def rule_text
    'Security Groups found ingress with port 22 or 3389'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'WU5'
  end

  def audit_impl(cfn_model)
    violating_security_groups = cfn_model.security_groups.select do |security_group|
      violating_ingresses = security_group.ingresses.select do |ingress|
        bad_port?(ingress.toPort) || bad_port?(ingress.fromPort)
      end

      !violating_ingresses.empty?
    end

    violating_ingresses = cfn_model.standalone_ingress.select do |standalone_ingress|
      bad_port?(standalone_ingress.toPort) || bad_port?(standalone_ingress.fromPort)
    end

    violating_security_groups.map(&:logical_resource_id) + violating_ingresses.map(&:logical_resource_id)
  end

  private

  def bad_port?(port)
    bad_ports = [22, 3389]
    bad_ports.include? port.to_i
  end
end
