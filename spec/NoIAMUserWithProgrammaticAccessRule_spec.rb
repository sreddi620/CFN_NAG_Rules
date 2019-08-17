require 'cfn-model'
require 'NoIAMUserWithProgrammaticAccessRule'

describe NoIAMUserWithProgrammaticAccessRule do
  context 'access key in template' do
    it 'returns offending logical resource ids' do
      cfn_model = CfnParser.new.parse IO.read('spec/test_templates/access_key.yml')

      actual_logical_resource_ids = NoIAMUserWithProgrammaticAccessRule.new.audit_impl cfn_model
      expected_logical_resource_ids = %w[AccessKey]

      expect(actual_logical_resource_ids).to eq expected_logical_resource_ids
    end
  end
end
