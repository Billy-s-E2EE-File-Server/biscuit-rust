defmodule BiscuitTest do
  use ExUnit.Case
  doctest Biscuit

  test "greets the world" do
    assert Biscuit.hello() == :world
  end
end
