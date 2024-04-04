# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.jprs.jp/jp/property_updates_on_error_out-of-range.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.jprs.jp.rb'

describe Whois::Parsers::WhoisJprsJp, "property_updates_on_error_out-of-range.expected" do

  subject do
    file = fixture("responses", "whois.jprs.jp/jp/property_updates_on_error_out-of-range.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2010-10-18 11:30:47 JST"))
    end
  end
end
