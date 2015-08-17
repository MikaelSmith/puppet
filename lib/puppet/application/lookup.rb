require 'puppet/application'
require 'puppet/pops/lookup'
require 'puppet/node'
require 'puppet/parser/compiler'

class Puppet::Application::Lookup < Puppet::Application

  RUNHELP = "Run 'puppet lookup --help for more details".freeze

  # Options for lookup
  option('--merge TYPE') do |arg|
    if %w{unique hash deep}.include?(arg)
      options[:merge] = arg
    else
      raise "The --merge option only accepts 'unique', 'hash', or 'deep' as arguments.\n#{RUNHELP}"
    end
  end

  option('--type TYPE_STRING') do |arg|
    options[:type] = arg
  end

  option('--knock_out_prefix PREFIX_STRING') do |arg|
    options[:prefix] = arg
  end

  option('--sort_merged_arrays')

  option('--unpack_arrays')

  option('--merge_hash_arrays')

  option('--explain')

  option('--default VALUE') do |arg|
    options[:default_value] = arg
  end

  # Options for facts/scope
  option('--node NODE_NAME') do |arg|
    options[:node] = arg
  end

  option('--facts FACT_FILE') do |arg|
    if %w{.yaml .yml .json}.include?(arg.match(/\.[^.]*$/)[0])
      options[:fact_file] = arg
    else
      raise "The --fact file only accepts yaml and json files as arguments.\n#{RUNHELP}"
    end
  end

  def run_command
    options[:keys] = command_line.args

    node = Puppet::Node.indirection.find("#{options[:node]}")
    compiler = Puppet::Parser::Compiler.new(node)
    compiler.compile
    scope = compiler.topscope

    require 'debugger'; debugger

    if options[:default_value]
     value = Puppet::Pops::Lookup.lookup(scope, options[:keys], options[:type], options[:default_value], true, {}, {}, options[:merge])
    else
      value = Puppet::Pops::Lookup.lookup(scope, options[:keys], options[:type], options[:default_value], false, {}, {}, options[:merge])
    end

    puts value
  end

end
