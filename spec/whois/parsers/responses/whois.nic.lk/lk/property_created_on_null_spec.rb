# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.lk/lk/property_created_on_null.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.nic.lk.rb'

describe Whois::Parsers::WhoisNicLk, "property_created_on_null.expected" do

  subject do
    file = fixture("responses", "whois.nic.lk/lk/property_created_on_null.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#created_on" do
    it do
      expect(subject.created_on).to eq(nil)
    end
  end
end
