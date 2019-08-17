require 'cfn-model'
require 'ElasticIPNotAllowedRule'

describe ElasticIPNotAllowedRule do
  context 'eip and eip assoc in template' do
    it 'returns offending logical resource ids' do
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/eips.yml')

      actual_logical_resource_ids = ElasticIPNotAllowedRule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[eip EipAssoc]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
