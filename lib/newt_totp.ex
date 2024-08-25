defmodule NewtTotp do
  @duration 30
  @digit_count 6

  # Test KEY "S4UQKKWHI6AN52OW3GEEG7I2W3VYM2M2"

  import Bitwise

  def generate_secret do
    :crypto.strong_rand_bytes(20)
  end

  def generate_totp(key) do
    {:ok, key} = Base.decode32(key)
    key
    |> hmac_sha1(calculate_T())
    |> truncate()
  end

  def valid?(secret, otp, since \\ nil),
    do: otp == generate_totp(secret) and not has_been_used?(since)

  defp truncate(hash) do
    # getting the last byte and masking it so we get a valid index
    offset = :binary.last(hash) &&& 0x0F
    # Extract 4 bytes starting from the calculated offset
    <<_::binary-size(offset), extracted_value::integer-size(32), _rest::binary>> = hash

    # Ensure the extracted value is positive
    extracted_positive_value = extracted_value &&& 0x7FFFFFFF

    # taking this number module to get the 06 digits
    otp = rem(extracted_positive_value, :math.pow(10, @digit_count) |> round())

    formatted_otp =
      otp
      |> Integer.to_string()
      |> String.pad_leading(6, "0")

    formatted_otp
  end

  defp hmac_sha1(key, t) do
    :crypto.mac(:hmac, :sha, key, t)
  end

  defp calculate_T(), do: <<Integer.floor_div(now_unix(), @duration)::64>>

  defp has_been_used?(nil), do: false

  defp has_been_used?(since),
    do: Integer.floor_div(now_unix(), @duration) <= Integer.floor_div(since, @duration)

  defp now_unix(), do: DateTime.utc_now() |> DateTime.to_unix()
end
