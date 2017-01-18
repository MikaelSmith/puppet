require 'puppet/application'
require 'puppet/error'

module ContractHelper
  begin
    require 'ffi'
    extend FFI::Library
    ffi_lib 'contract'

    CTFS_ROOT = '/system/contract'
    CT_TEMPLATE = CTFS_ROOT+'/process/template'
    CT_LATEST = CTFS_ROOT+'/process/latest'
    CT_PR_PGRPONLY = 0x4
    CT_PR_EV_HWERR = 0x20
    CTD_COMMON = 0

    attach_function :ct_tmpl_activate, [:int], :int
    attach_function :ct_tmpl_clear, [:int], :int
    attach_function :ct_ctl_abandon, [:int], :int

    attach_function :ct_pr_tmpl_set_param, [:int, :int], :int
    attach_function :ct_pr_tmpl_set_fatal, [:int, :int], :int
    attach_function :ct_tmpl_set_critical, [:int, :int], :int
    attach_function :ct_tmpl_set_informative, [:int, :int], :int

    attach_function :ct_status_read, [:int, :int, :pointer], :int
    attach_function :ct_status_get_id, [:pointer], :int
    attach_function :ct_status_free, [:pointer], :void

    def ContractHelper.activate_new_contract_template()
      tmpl_fd = IO.sysopen(CT_TEMPLATE, 'r+')
      Puppet.fatal "Unable to access contract template" if tmpl_fd == -1

      begin
        raise if 0 != ct_pr_tmpl_set_param(tmpl_fd, CT_PR_PGRPONLY)
        raise if 0 != ct_pr_tmpl_set_param(tmpl_fd, CT_PR_PGRPONLY)
        raise if 0 != ct_tmpl_set_critical(tmpl_fd, 0)
        raise if 0 != ct_tmpl_set_informative(tmpl_fd, CT_PR_EV_HWERR)

        raise if 0 != ct_tmpl_activate(tmpl_fd)
      rescue
        close(tmpl_fd)
        Puppet.fatal "Unable to modify contract"
      end

      return tmpl_fd
    end

    def ContractHelper.deactivate_contract_template(tmpl_fd)
      return 0 if tmpl_fd < 0

      err = ct_tmpl_clear(tmpl_fd)
      close(tmpl_fd)
      Puppet.fatal "Unable to deactivate contract template" if err != 0
    end

    def get_latest_child_contract_id()
      stat_fd = IO.sysopen(CT_LATEST, 'r')
      Puppet.fatal "Unable to access contract latest" if tmpl_fd == -1

      FFI::MemoryPointer.new(:pointer) do |stathdl|
        ctid = -1

        if 0 == ct_status_read(stat_fd, CTD_COMMON, stathdl)
          ctid = ct_status_get_id(stathdl)
          ct_status_free(stathdl)
        end

        close(stat_fd)

        Puppet.fatal "Unable to read contract stats" if ctid < 0

        return ctid
      end
    end

    def ContractHelper.abandon_latest_child_contract()
      ctid = get_latest_child_contract_id

      ctl_fd = IO.sysopen(CTFS_ROOT + '/process/' + ctid + '/ctl', 'w')
      Puppet.fatal "Unable to read latest child contract" if ctl_fd < 0

      err = ct_ctl_abandon(ctl_fd)
      close(ctl_fd)

      Puppet.fatal "Failed to abandon contract created for a child process" if err != 0
    end
  rescue LoadError
    Puppet.debug "Solaris contracts unavailable"

    def ContractHelper.activate_new_contract_template()
    end

    def ContractHelper.deactivate_contract_template(tmpl_fd)
    end

    def ContractHelper.abandon_latest_child_contract()
    end
  end
end

# A general class for triggering a run of another
# class.
class Puppet::Agent
  require 'puppet/agent/locker'
  include Puppet::Agent::Locker

  require 'puppet/agent/disabler'
  include Puppet::Agent::Disabler

  require 'puppet/util/splayer'
  include Puppet::Util::Splayer

  attr_reader :client_class, :client, :should_fork

  def initialize(client_class, should_fork=true)
    @should_fork = can_fork? && should_fork
    @client_class = client_class
  end

  def can_fork?
    Puppet.features.posix? && RUBY_PLATFORM != 'java'
  end

  def needing_restart?
    Puppet::Application.restart_requested?
  end

  # Perform a run with our client.
  def run(client_options = {})
    if disabled?
      Puppet.notice "Skipping run of #{client_class}; administratively disabled (Reason: '#{disable_message}');\nUse 'puppet agent --enable' to re-enable."
      return
    end

    result = nil
    block_run = Puppet::Application.controlled_run do
      splay client_options.fetch :splay, Puppet[:splay]
      result = run_in_fork(should_fork) do
        with_client(client_options[:transaction_uuid]) do |client|
          begin
            client_args = client_options.merge(:pluginsync => Puppet::Configurer.should_pluginsync?)
            lock { client.run(client_args) }
          rescue Puppet::LockError
            Puppet.notice "Run of #{client_class} already in progress; skipping  (#{lockfile_path} exists)"
            return
          rescue StandardError => detail
            Puppet.log_exception(detail, "Could not run #{client_class}: #{detail}")
          end
        end
      end
      true
    end
    Puppet.notice "Shutdown/restart in progress (#{Puppet::Application.run_status.inspect}); skipping run" unless block_run
    result
  end

  def stopping?
    Puppet::Application.stop_requested?
  end

  def run_in_fork(forking = true)
    return yield unless forking or Puppet.features.windows?

    tmpl_fd = ContractHelper.activate_new_contract_template

    child_pid = Kernel.fork do
      ContractHelper.deactivate_contract_template(tmpl_fd)

      $0 = "puppet agent: applying configuration"
      begin
        exit(yield)
      rescue SystemExit
        exit(-1)
      rescue NoMemoryError
        exit(-2)
      end
    end

    ContractHelper.deactivate_contract_template(tmpl_fd)
    ContractHelper.abandon_latest_child_contract

    exit_code = Process.waitpid2(child_pid)
    case exit_code[1].exitstatus
    when -1
      raise SystemExit
    when -2
      raise NoMemoryError
    end
    exit_code[1].exitstatus
  end

  private

  # Create and yield a client instance, keeping a reference
  # to it during the yield.
  def with_client(transaction_uuid)
    begin
      @client = client_class.new(Puppet::Configurer::DownloaderFactory.new, transaction_uuid)
    rescue StandardError => detail
      Puppet.log_exception(detail, "Could not create instance of #{client_class}: #{detail}")
      return
    end
    yield @client
  ensure
    @client = nil
  end
end
