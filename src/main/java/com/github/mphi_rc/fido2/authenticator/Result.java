package com.github.mphi_rc.fido2.authenticator;

import java.util.Optional;
import java.util.function.Function;

import org.immutables.value.Value;

import com.google.common.base.Preconditions;

@Value.Immutable
public abstract class Result<T, E> {

	@Value.Immutable
	public static abstract class ResultHandler<X, T, E> {
		
		@Value.Parameter
		protected abstract Result<T, E> result();
		
		@Value.Parameter
		protected abstract Optional<X> handledError();
		
		public X elseGet(Function<T, X> f) {
			return handledError().orElseGet(() -> f.apply(result().value().get()));
		}
	}
	
	protected abstract Optional<T> value();
	protected abstract Optional<E> error();

	public static <T, E> Result<T, E> ok(T value) {
		return ImmutableResult.<T, E>builder()
				.value(value)
				.build();
	}

	public static <T, E> Result<T, E> err(E e) {
		return ImmutableResult.<T, E>builder()
				.error(e)
				.build();
	}
	
	public <X> ResultHandler<X, T, E> handleError(Function<E, X> f) {
		return ImmutableResultHandler.of(this, error().map(f::apply));
	}

	@Value.Check
	protected void check() {
		Preconditions.checkArgument((value().isPresent() && !error().isPresent())
				|| (!value().isPresent() && error().isPresent()),
				"A result has either a value or an error");
	}
}
