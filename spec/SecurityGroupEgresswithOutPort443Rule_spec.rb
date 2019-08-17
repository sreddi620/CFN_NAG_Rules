require 'cfn-model'
require 'SecurityGroupEgresswithOutPort443Rule'

describe SecurityGroupEgresswithOutPort443Rule do
  context 'egresses besides 443' do
    it 'returns offending logical resource ids' do
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/sg_egress_other_then_443.json')

      actual_logical_resource_ids = SecurityGroupEgresswithOutPort443Rule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[sgEgress34 anotherSg egress443-2]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
