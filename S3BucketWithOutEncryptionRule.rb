# frozen_string_literal: true

require 'cfn-nag/violation'
require_relative 'base'

class S3BucketWithOutEncryptionRule < BaseRule
  def rule_text
    'S3 Bucket likely should have encryption enabled'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'WU4'
  end

  def audit_impl(cfn_model)
    violating_buckets = cfn_model.resources_by_type('AWS::S3::Bucket').select do |bucket|
      bucket.bucketEncryption.nil?
    end

    violating_buckets.map(&:logical_resource_id)
  end
end
