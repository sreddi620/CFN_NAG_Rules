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
    'WU_Violation_4'
  end

  def audit_impl(cfn_model)
    logical_resource_ids = []

    cfn_model.resources_by_type('AWS::S3::Bucket').each do |bucket|
      logical_resource_ids << bucket.logical_resource_id if bucket.bucketEncryption.serverSideEncryptionConfiguration.serverSideEncryptionByDefault.sSEAlgorithm != 'AES256'
    end

    logical_resource_ids
  end
end
