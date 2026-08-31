defmodule Postgrex.TypeManager do
  @moduledoc false

  use GenServer

  def start_link(_) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def locate(module, key) do
    GenServer.call(__MODULE__, {:locate, module, key, self()})
  end

  @impl true
  def init(:ok) do
    Process.flag(:trap_exit, true)
    {:ok, %{}}
  end

  @impl true
  def handle_call({:locate, module, key, starter}, _from, servers) do
    pair = {module, key}

    case servers do
      %{^pair => pid} ->
        if Process.alive?(pid) do
          {:reply, pid, servers}
        else
          start_and_reply(module, pair, starter, servers)
        end

      %{} ->
        start_and_reply(module, pair, starter, servers)
    end
  end

  @impl true
  def handle_info({:EXIT, pid, _reason}, servers) do
    servers =
      servers
      |> Enum.reject(fn {_pair, server} -> server == pid end)
      |> Map.new()

    {:noreply, servers}
  end

  defp start_and_reply(module, pair, starter, servers) do
    {:ok, pid} = Postgrex.TypeServer.start_link({module, starter, []})
    {:reply, pid, Map.put(servers, pair, pid)}
  end
end
