# ChengTianmingshelp
Simple and easy way to hide plain text strings in SO files.
/*

* Copyright 2026 Justas Masiulis
* 
* Unless you comply with this license, you may not use this file.
* You may obtain a copy of the license at:
* 
* https://github.com/ChengTian666905/ChengTianmingshelp.git
* 
* Unless required by applicable law or agreed to in writing,
* software distributed under this license is provided "AS IS",
* WITHOUT ANY WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the license for the specific language governing permissions and
* limitations under the license.
* Anyone who modifies this code shall have their entire family die.*/


#ifndef JM_XORSTR_HPP
#define JM_XORSTR_HPP

// ============ BY.CHENGTIANXORSTR ============

#include <cstdint>
#include <cstddef>
#include <utility>
#include <type_traits>

#define xorstr(str) ::jm::xor_string([]() { return str; }, std::integral_constant<std::size_t, sizeof(str) / sizeof(*str)>{}, std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#define xorstr_(str) xorstr(str).crypt_get()

#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#else
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#endif

namespace jm {

    namespace detail {

        template<std::size_t Size>
        XORSTR_FORCEINLINE constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<std::uint32_t Seed>
        XORSTR_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for(char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        XORSTR_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part  = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        // loads up to 8 characters of string into uint64 and xors it with the key
        template<std::size_t N, class CharT>
        XORSTR_FORCEINLINE constexpr std::uint64_t
        load_xored_str8(std::uint64_t key, std::size_t idx, const CharT* str) noexcept
        {
            using cast_type = typename std::make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof(CharT);
            constexpr auto idx_offset = 8 / value_size;

            std::uint64_t value = key;
            for(std::size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i)
                value ^=
                    (std::uint64_t{ static_cast<cast_type>(str[i + idx * idx_offset]) }
                     << ((i % idx_offset) * 8 * value_size));

            return value;
        }

        // forces compiler to use registers instead of stuffing constants in rdata
        XORSTR_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) :);
            return value;
#else
            volatile std::uint64_t reg = value;
            return reg;
#endif
        }

    } // namespace detail

    template<class CharT, std::size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, std::size_t Size, std::uint64_t... Keys, std::size_t... Indices>
    class xor_string<CharT, Size, std::integer_sequence<std::uint64_t, Keys...>, std::index_sequence<Indices...>> {
        constexpr static inline std::uint64_t alignment = 16;
        alignas(alignment) std::uint64_t _storage[sizeof...(Keys)];

    public:
        using value_type    = CharT;
        using size_type     = std::size_t;
        using pointer       = CharT*;
        using const_pointer = const CharT*;

        template<class L>
        XORSTR_FORCEINLINE xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) noexcept
            : _storage{ ::jm::detail::load_from_reg((std::integral_constant<std::uint64_t, detail::load_xored_str8<Size>(Keys, Indices, l())>::value))... }
        {}

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return Size - 1;
        }

        // ===== 纯标量解密（替代所有 SIMD 指令）=====
        XORSTR_FORCEINLINE void crypt() noexcept
        {
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
            constexpr std::size_t num_keys = sizeof...(Keys);
            for (std::size_t i = 0; i < num_keys; ++i) {
                _storage[i] ^= keys[i];
            }
        }

        XORSTR_FORCEINLINE const_pointer get() const noexcept
        {
            return reinterpret_cast<const_pointer>(_storage);
        }

        XORSTR_FORCEINLINE pointer get() noexcept
        {
            return reinterpret_cast<pointer>(_storage);
        }

        // ★★★ 关键修改：返回类型改为 const_pointer ★★★
        XORSTR_FORCEINLINE const_pointer crypt_get() noexcept
        {
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
            constexpr std::size_t num_keys = sizeof...(Keys);
            for (std::size_t i = 0; i < num_keys; ++i) {
                _storage[i] ^= keys[i];
            }
            return reinterpret_cast<const_pointer>(_storage);
        }
    };

    template<class L, std::size_t Size, std::size_t... Indices>
    xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) -> xor_string<
                std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>,
                Size,
                std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>,
                std::index_sequence<Indices...>>;

} // namespace jm

#endif // include guard
