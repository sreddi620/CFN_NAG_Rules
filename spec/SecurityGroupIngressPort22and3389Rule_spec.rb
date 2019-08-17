require 'cfn-model'
require 'SecurityGroupIngressPort22and3389Rule'

describe SecurityGroupIngressPort22and3389Rule do
  context 'ingress besides 22, 3389' do
    it 'returns offending logical resource ids' do
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/sg_ingress_other_then_22_3389.json')

      actual_logical_resource_ids = SecurityGroupIngressPort22and3389Rule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[sgIngress22 anotherSg ingress22-2]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
