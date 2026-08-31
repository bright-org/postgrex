defmodule Postgrex.TypeSupervisor do
  @moduledoc false

  use Supervisor

  @doc """
  Starts a type supervisor and a manager for type servers.
  """
  def start_link(_) do
    Supervisor.start_link(__MODULE__, :ok)
  end

  @doc """
  Locates a type server for the given module-key pair.
  """
  def locate(module, key) do
    Postgrex.TypeManager.locate(module, key)
  end

  @impl true
  def init(:ok) do
    Supervisor.init([Postgrex.TypeManager], strategy: :one_for_one)
  end
end
