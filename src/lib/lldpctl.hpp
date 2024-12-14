/**
 * @brief lldpctl API C++ wrapper
 */

#pragma once

/* *** includes ***************************************************************/

#include <cstddef>
#include <optional>
#include <vector>
#include <list>
#include <map>
#include <memory>
#include <span>
#include <functional>
#include <thread>
#include <mutex>

#include <lldpctl.h>

/* *** defines ****************************************************************/

#ifndef __stringify_1
#  define __stringify_1(x) #  x
#endif

#ifndef __stringify
#  define __stringify(x) __stringify_1(x)
#endif

#define CHECK_LLDP_GENERIC(failed, __call, ...) \
  do {                                          \
    if (failed(__call)) {                       \
      __VA_ARGS__;                              \
    }                                           \
  } while (0)

#define FAILED_NULL(p) ((p) == nullptr)
#define CHECK_LLDP_P(__call, conn)                                       \
  CHECK_LLDP_GENERIC(                                                    \
      FAILED_NULL, __call, const auto _rc_ { lldpctl_last_error(conn) }; \
      if (LLDPCTL_NO_ERROR != _rc_) {                                    \
  throw std::system_error(std::error_code(_rc_, LldpErrCategory()),      \
      "'" __stringify(__call) "' failed");                               \
      })

#define FAILED_NEGATIVE(v) ((v) < 0)
#define CHECK_LLDP_N(__call, conn)                                                     \
  CHECK_LLDP_GENERIC(FAILED_NEGATIVE, __call,                                          \
		     const auto _rc_ { lldpctl_last_error(conn) };                     \
		     throw std::system_error(std::error_code(_rc_, LldpErrCategory()), \
			 "'" __stringify(__call) "' failed");)

#define CHECK_LLDP_N2(pre, __call, conn)                            \
  CHECK_LLDP_GENERIC(                                               \
      FAILED_NEGATIVE, __call, if (pre) {                           \
  const auto _rc_ { lldpctl_last_error(conn) };                     \
  throw std::system_error(std::error_code(_rc_, LldpErrCategory()), \
      "'" __stringify(__call) "' failed");                          \
      })

/* *** type declarations ******************************************************/

/* *** exported interfaces ****************************************************/

namespace lldpcli {
namespace literals {
/**
 * @brief Operator to define std::byte literals.
 *
 * Example: auto byte{ 0x01_b };
 */
consteval std::byte operator"" _b(unsigned long long int value)
{
	return static_cast<std::byte>(value);
}
} // namespace literals

/**
 * @brief LLDP error category.
 */
class LldpErrCategory : public std::error_category {
    public:
	const char *name() const noexcept override { return "lldpctl"; }

	std::string message(int ev) const override
	{
		return ::lldpctl_strerror(static_cast<lldpctl_error_t>(ev));
	}
};

/**
 * @brief Wrapper class for @p lldpctl_atom_t with automatic lifetime management.
 */
class LldpAtom {
    public:
	using vector = std::vector<std::byte>;
	using span = std::span<const std::byte>;

	/**
	 * @brief Construct a new Lldp Atom.
	 *
	 * @param atom          The atom provided by the library.
	 * @param inc_ref_cnt   If @p true increment the atom's reference count as
	 * ownership is not implicitly transferred from the caller.
	 * @param conn          The connection the atom belongs to. Used to extend the
	 * connection lifetime as the atom can't live without it. May be @p nullptr in
	 * which case the connection's lifetime can't be extended by the atom object
	 * (e.g. as the connection is owned by the library).
	 * @param parent        The optional parent atom. Used to extend the parent
	 * atom's lifetime as the child atom can't live without it.
	 */
	explicit LldpAtom(lldpctl_atom_t *atom, bool inc_ref_cnt,
	    const std::shared_ptr<lldpctl_conn_t> &conn,
	    std::unique_ptr<LldpAtom> parent = nullptr)
	    : atom_(atom)
	    , conn_(conn)
	    , parent_(std::move(parent))
	{
		if (inc_ref_cnt) {
			::lldpctl_atom_inc_ref(atom_);
		}
	}

	~LldpAtom()
	{
		if (atom_) {
			::lldpctl_atom_dec_ref(atom_);
		}
	}

	LldpAtom(const LldpAtom &other) noexcept
	    : atom_(other.atom_)
	    , conn_(other.conn_)
	    , parent_(
		  other.parent_ ? std::make_unique<LldpAtom>(*other.parent_) : nullptr)
	{
		::lldpctl_atom_inc_ref(atom_);
	}

	LldpAtom &operator=(const LldpAtom &other)
	{
		if (this != &other) {
			atom_ = other.atom_;
			conn_ = other.conn_;
			parent_ = other.parent_ ?
			    std::make_unique<LldpAtom>(*other.parent_) :
			    nullptr;
			::lldpctl_atom_inc_ref(atom_);
		}

		return *this;
	}

	LldpAtom(LldpAtom &&other) noexcept
	    : atom_(other.atom_)
	    , conn_(other.conn_)
	    , parent_(std::move(other.parent_))
	{
		other.atom_ = nullptr;
		other.conn_ = nullptr;
		other.parent_ = nullptr;
	}

	LldpAtom &operator=(LldpAtom &&other) noexcept
	{
		if (this != &other) {
			atom_ = other.atom_;
			conn_ = other.conn_;
			parent_ = std::move(other.parent_);
			other.atom_ = nullptr;
			other.conn_ = nullptr;
			other.parent_ = nullptr;
		}

		return *this;
	}

	LldpAtom GetPort() const
	{
		lldpctl_atom_t *atom;
		CHECK_LLDP_P(atom = ::lldpctl_get_port(atom_), conn_.get());
		return LldpAtom { atom, false, conn_ };
	}

	std::optional<LldpAtom> GetAtom(lldpctl_key_t key) const
	{
		auto atom { ::lldpctl_atom_get(atom_, key) };
		return atom ? std::make_optional<LldpAtom>(atom, false, conn_) :
			      std::nullopt;
	}

	LldpAtom CreateAtom() const
	{
		lldpctl_atom_t *atom;
		CHECK_LLDP_P(atom = ::lldpctl_atom_create(atom_), conn_.get());
		/* Store the parent atom to increase its reference count so that it
		 * remains living as long as the child lives. */
		return LldpAtom { atom, false, conn_,
			std::make_unique<LldpAtom>(*this) };
	}

	void SetAtom(lldpctl_key_t key, const LldpAtom &child)
	{
		CHECK_LLDP_P(::lldpctl_atom_set(atom_, key, child.atom_), conn_.get());
	}

	std::list<LldpAtom> GetAtomList(lldpctl_key_t key) const
	{
		lldpctl_atom_t *it;
		CHECK_LLDP_P(it = ::lldpctl_atom_get(atom_, key), conn_.get());

		std::list<LldpAtom> list;
		lldpctl_atom_t *atom;
		lldpctl_atom_foreach(it, atom)
		{
			list.emplace_back(atom, true, conn_);
		}

		return list;
	}

	template <typename T> auto GetValue(lldpctl_key_t key) const
	{
		if constexpr (std::is_same_v<T, std::string> ||
		    std::is_same_v<T, std::string_view>) {
			const auto str { ::lldpctl_atom_get_str(atom_, key) };
			return str ? std::make_optional<T>(str) : std::nullopt;
		} else if constexpr (std::is_same_v<T, int>) {
			const auto value { ::lldpctl_atom_get_int(atom_, key) };
			return lldpctl_last_error(lldpctl_atom_get_connection(atom_)) ==
				LLDPCTL_NO_ERROR ?
			    std::make_optional<T>(value) :
			    std::nullopt;
		} else if constexpr (std::is_same_v<T, vector> ||
		    std::is_same_v<T, span>) {
			size_t length { 0 };
			const auto buffer { ::lldpctl_atom_get_buffer(atom_, key,
			    &length) };

			if (buffer) {
				auto it { reinterpret_cast<const std::byte *>(buffer) };
				return T { it, it + length };
			} else {
				return T {};
			}
		} else {
			static_assert(always_false_<T>::value, "Unsupported type");
		}
	}

	template <typename T> void SetValue(lldpctl_key_t key, const T &data)
	{
		if constexpr (std::is_same_v<T, std::optional<std::string>> ||
		    std::is_same_v<T, std::optional<std::string_view>>) {
			CHECK_LLDP_P(::lldpctl_atom_set_str(atom_, key,
					 data.has_value() ? data->data() : nullptr),
			    conn_.get());
		} else if constexpr (std::is_same_v<T, int>) {
			CHECK_LLDP_P(::lldpctl_atom_set_int(atom_, key, data),
			    conn_.get());
		} else if constexpr (std::is_same_v<T, vector> ||
		    std::is_same_v<T, span>) {
			CHECK_LLDP_P(::lldpctl_atom_set_buffer(atom_, key,
					 reinterpret_cast<const uint8_t *>(data.data()),
					 data.size()),
			    conn_.get());
		} else {
			static_assert(always_false_<T>::value, "Unsupported type");
		}
	}

    private:
	template <typename> struct always_false_ : std::false_type {
	};

	lldpctl_atom_t *atom_;
	std::shared_ptr<lldpctl_conn_t> conn_;
	std::unique_ptr<LldpAtom> parent_;
};

/**
 * @brief Wrapper class for @p lldpctl_conn_t with automatic lifetime management.
 */
class LldpCtl {
    public:
	explicit LldpCtl()
	{
		if (!conn_) {
			throw std::system_error(std::error_code(LLDPCTL_ERR_NOMEM,
						    LldpErrCategory()),
			    "Could not create lldpctl connection.");
		}
	}

	~LldpCtl() = default;

	LldpCtl(const LldpCtl &other) = default;

	LldpCtl &operator=(const LldpCtl &other)
	{
		if (this != &other) {
			conn_ = other.conn_;
		}

		return *this;
	}

	LldpCtl(LldpCtl &&other) noexcept
	    : conn_(other.conn_)
	{
		other.conn_ = nullptr;
	}

	LldpCtl &operator=(LldpCtl &&other) noexcept
	{
		if (this != &other) {
			conn_ = other.conn_;
			other.conn_ = nullptr;
		}

		return *this;
	}

	LldpAtom GetConfiguration() const
	{
		lldpctl_atom_t *atom;
		CHECK_LLDP_P(atom = ::lldpctl_get_configuration(conn_.get()),
		    conn_.get());
		return LldpAtom { atom, false, conn_ };
	}

	std::list<LldpAtom> GetInterfaces() const
	{
		const auto &it { ::lldpctl_get_interfaces(conn_.get()) };

		std::list<LldpAtom> list;
		lldpctl_atom_t *atom;
		lldpctl_atom_foreach(it, atom)
		{
			list.emplace_back(atom, true, conn_);
		}

		return list;
	}

	std::optional<LldpAtom> GetInterface(std::string_view if_name) const
	{
		for (const auto &interface : GetInterfaces()) {
			if (interface.GetValue<std::string_view>(
				lldpctl_k_interface_name) == if_name) {
				return interface;
			}
		}

		return std::nullopt;
	}

	LldpAtom GetLocalChassis() const
	{
		lldpctl_atom_t *atom;
		CHECK_LLDP_P(atom = ::lldpctl_get_local_chassis(conn_.get()),
		    conn_.get());
		return LldpAtom { atom, false, conn_ };
	}

	LldpAtom GetDefaultPort() const
	{
		lldpctl_atom_t *atom;
		CHECK_LLDP_P(atom = ::lldpctl_get_default_port(conn_.get()),
		    conn_.get());
		return LldpAtom { atom, false, conn_ };
	}

	static std::string_view get_default_transport() noexcept
	{
		return ::lldpctl_get_default_transport();
	}

	static std::map<std::string, int, std::less<>> KeyGetMap(
	    lldpctl_key_t key) noexcept
	{
		std::map<std::string, int, std::less<>> map;

		lldpctl_map_t *entry { ::lldpctl_key_get_map(key) };
		while (entry->string) {
			map.try_emplace(entry->string, entry->value);
			++entry;
		}

		return map;
	}

    private:
	std::shared_ptr<lldpctl_conn_t> conn_ { ::lldpctl_new(nullptr, nullptr, this),
		&::lldpctl_release };
};

/**
 * @brief Wrapper for change callback registration.
 *
 * @tparam X Context pointer type for the general optional callback passed to the
 * constructor.
 * @tparam Y Context pointer type for the interface specific callbacks passed to @ref
 * RegisterInterfaceCallback.
 */
template <typename X = void, typename Y = void> class LldpWatch {
    public:
	template <typename C>
	using ChangeCallback =
	    const std::function<void(std::string_view if_name, lldpctl_change_t change,
		const LldpAtom interface, const LldpAtom neighbor, C *ctx)>;

	/**
	 * @brief Construct a new Lldp Watch object.
	 *
	 * @param callback  Optional callback to trigger on remote changes.
	 *                  Additionally, interface specific callbacks can be registered
	 * using @ref RegisterInterfaceCallback.
	 * @param ctx       Optional context passed to @p callback.
	 */
	explicit LldpWatch(
	    const std::optional<ChangeCallback<X>> &callback = std::nullopt,
	    const X *ctx = nullptr)
	    : general_callback_(callback.has_value() ?
		      std::make_optional(
			  std::make_pair(*callback, const_cast<X *>(ctx))) :
		      std::nullopt)
	{
		if (!conn_) {
			throw std::system_error(std::error_code(LLDPCTL_ERR_NOMEM,
						    LldpErrCategory()),
			    "Could not create lldpctl connection.");
		}

		CHECK_LLDP_N(::lldpctl_watch_callback2(conn_,
				 &LldpWatch<X, Y>::WatchCallback,
				 static_cast<void *>(this)),
		    conn_);

		thread_ = std::jthread { [this](std::stop_token stop) {
			while (!stop.stop_requested()) {
				CHECK_LLDP_N2(!stop.stop_requested(),
				    ::lldpctl_watch(conn_), conn_);
			}
		} };
	}

	~LldpWatch()
	{
		if (conn_) {
			thread_.request_stop();
			::lldpctl_watch_sync_unblock(conn_);
			thread_.join();
			::lldpctl_release(conn_);
		}
	}

	LldpWatch(const LldpWatch &) = delete;
	LldpWatch &operator=(const LldpWatch &) = delete;
	LldpWatch(LldpWatch &&other) = delete;
	LldpWatch &operator=(LldpWatch &&) = delete;

	/**
	 * @brief Register an interface specific callback on remote changes.
	 *
	 * @param if_name       The local interface to monitor.
	 * @param callback      Callback to trigger on remote changes.
	 * @param ctx           Optional context passed to @p callback.
	 * @param trigger_init  It @p true then @p callback is invoked during
	 * registration for all existing neighbors.
	 */
	void RegisterInterfaceCallback(const std::string &if_name,
	    ChangeCallback<Y> callback, const Y *ctx, bool trigger_init = false)
	{
		const auto interface {
			LldpCtl().GetInterface(if_name)
		};
		if (!interface.has_value()) {
			throw std::system_error(std::error_code(LLDPCTL_ERR_NOT_EXIST,
						    LldpErrCategory()),
			    "Couldn't find interface '" + if_name + "'");
		}

		std::scoped_lock lock { mutex_ };

		/**
		 * Note:
		 * There's a race one way or the other - we decided to accept the one
		 * that the neighbor changes between reading it and registering the
		 * callback.
		 */
		if (trigger_init) {
			for (const auto &neighbor : interface->GetPort().GetAtomList(
				 lldpctl_k_port_neighbors)) {
				callback(if_name, lldpctl_change_t::lldpctl_c_added,
				    *interface, neighbor, const_cast<Y *>(ctx));
			}
		}

		interface_callbacks_.try_emplace(if_name,
		    std::make_pair(callback, const_cast<Y *>(ctx)));
	}

    private:
	static void WatchCallback(lldpctl_change_t change, lldpctl_atom_t *interface,
	    lldpctl_atom_t *neighbor, void *p)
	{
		/* These LldpAtoms don't extend the lifetime of the underlying
		 * connection as it's owned by the library. */
		LldpAtom interface_atom { interface, true, nullptr };
		LldpAtom neighbor_atom { neighbor, true, nullptr };

		const auto if_name { *interface_atom.GetValue<std::string_view>(
		    lldpctl_k_interface_name) };

		auto self { static_cast<LldpWatch<X, Y> *>(p) };

		std::scoped_lock lock { self->mutex_ };

		if (self->general_callback_.has_value()) {
			auto [callback, ctx] { self->general_callback_.value() };
			callback(if_name, change, interface_atom, neighbor_atom, ctx);
		}

		if (auto it { self->interface_callbacks_.find(if_name) };
		    it != self->interface_callbacks_.end()) {
			auto [callback, ctx] { it->second };
			callback(if_name, change, interface_atom, neighbor_atom, ctx);
		}
	}

	lldpctl_conn_t *conn_ { ::lldpctl_new(nullptr, nullptr, this) };
	std::jthread thread_;
	std::mutex mutex_;
	const std::optional<std::pair<ChangeCallback<X>, X *>> general_callback_;
	std::map<std::string, std::pair<ChangeCallback<Y>, Y *>, std::less<>>
	    interface_callbacks_;
};

} // namespace lldpcli
