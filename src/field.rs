use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{AegisError, AegisResult};
use crate::keygen::fill_random_bytes;

/// The eighth Mersenne prime: `p = 2^31 - 1 = 2_147_483_647`.
///
/// Serves as the prime modulus for the finite field `GF(p)`.
pub const FIELD_PRIME: u32 = 2_147_483_647;

/// Bitmask for extracting 31 bits (`0x7FFF_FFFF = 2^31 - 1`) during rejection sampling.
const BITMASK_31: u32 = 0x7FFF_FFFF;

/// An element of the prime finite field `GF(2^31 - 1)`.
///
/// Invariant: `0 <= self.value < FIELD_PRIME` at all times.
#[derive(Clone, Copy, Default, Zeroize)]
pub struct FieldElement {
    value: u32,
}

impl FieldElement {
    /// Additive identity element (`0 mod p`).
    pub const ZERO: Self = Self { value: 0 };

    /// Multiplicative identity element (`1 mod p`).
    pub const ONE: Self = Self { value: 1 };

    /// Constructs a `FieldElement` from a `u32` that is already strictly less than `FIELD_PRIME`.
    ///
    /// Returns `Err(AegisError::FieldValueOutOfRange)` if `val >= FIELD_PRIME`.
    #[inline]
    pub fn from_canonical(val: u32) -> AegisResult<Self> {
        if val >= FIELD_PRIME {
            return Err(AegisError::FieldValueOutOfRange);
        }
        Ok(Self { value: val })
    }

    /// Constructs a `FieldElement` by reducing an arbitrary `u64` modulo `FIELD_PRIME`.
    #[inline]
    pub const fn from_reduced(val: u64) -> Self {
        Self {
            value: (val % (FIELD_PRIME as u64)) as u32,
        }
    }

    /// Samples a uniformly distributed random element in `GF(p)` using OS CSPRNG
    /// and 31-bit rejection sampling (eliminating modulo bias).
    pub fn random() -> AegisResult<Self> {
        let mut buf = [0u8; 4];
        loop {
            fill_random_bytes(&mut buf)?;
            let candidate = u32::from_le_bytes(buf) & BITMASK_31;
            buf.zeroize();
            if candidate < FIELD_PRIME {
                return Ok(Self { value: candidate });
            }
        }
    }

    /// Samples a uniformly distributed **non-zero** random element in `GF(p)*`.
    /// Useful for choosing highest-degree polynomial coefficients.
    pub fn random_nonzero() -> AegisResult<Self> {
        loop {
            let elem = Self::random()?;
            if !elem.is_zero() {
                return Ok(elem);
            }
        }
    }

    /// Returns the canonical `u32` representation in `0..FIELD_PRIME`.
    #[inline]
    pub const fn value(self) -> u32 {
        self.value
    }

    /// Constant-time check for whether this element is the additive identity (`0`).
    #[inline]
    pub fn is_zero(self) -> bool {
        bool::from(self.value.ct_eq(&0))
    }

    /// Modular addition: `(self + rhs) mod p`.
    ///
    /// Uses `u64` intermediate arithmetic so overflow is impossible.
    #[inline]
    pub const fn add_mod(self, rhs: Self) -> Self {
        let sum = (self.value as u64) + (rhs.value as u64);
        Self::from_reduced(sum)
    }

    /// Modular subtraction: `(self - rhs) mod p`.
    ///
    /// Adds `FIELD_PRIME` in `u64` space before subtracting to avoid underflow.
    #[inline]
    pub const fn sub_mod(self, rhs: Self) -> Self {
        let diff = (self.value as u64) + (FIELD_PRIME as u64) - (rhs.value as u64);
        Self::from_reduced(diff)
    }

    /// Modular negation: `(-self) mod p`.
    #[inline]
    pub const fn neg_mod(self) -> Self {
        if self.value == 0 {
            Self::ZERO
        } else {
            Self {
                value: FIELD_PRIME - self.value,
            }
        }
    }

    /// Modular multiplication: `(self * rhs) mod p`.
    ///
    /// Since `self, rhs < 2^31 - 1`, their product is `< 2^62`, fitting comfortably
    /// inside `u64` without overflow.
    #[inline]
    pub const fn mul_mod(self, rhs: Self) -> Self {
        let prod = (self.value as u64) * (rhs.value as u64);
        Self::from_reduced(prod)
    }

    /// Modular exponentiation: `self^exp mod p` via binary square-and-multiply.
    ///
    /// Runs in `O(log(exp))` field multiplications.
    pub const fn pow_mod(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::ONE;

        while exp > 0 {
            if (exp & 1) == 1 {
                result = result.mul_mod(base);
            }
            base = base.mul_mod(base);
            exp >>= 1;
        }
        result
    }

    /// Computes the multiplicative inverse `self^(-1) mod p` using Fermat's Little Theorem:
    /// `a^(p - 2) === a^(-1) (mod p)` for all `a != 0 (mod p)`.
    ///
    /// Returns `Err(AegisError::DivisionByZero)` if `self == 0`.
    pub fn inverse(self) -> AegisResult<Self> {
        if self.is_zero() {
            return Err(AegisError::DivisionByZero);
        }
        Ok(self.pow_mod((FIELD_PRIME - 2) as u64))
    }

    /// Modular division: `(self * rhs^(-1)) mod p`.
    pub fn div_mod(self, rhs: Self) -> AegisResult<Self> {
        let inv = rhs.inverse()?;
        Ok(self.mul_mod(inv))
    }
}

/// Evaluates a polynomial `f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[k-1]*x^(k-1) (mod p)`
/// at point `x` using Horner's Method in `O(k)` field operations.
///
/// If `coeffs` is empty, returns `FieldElement::ZERO`.
pub fn evaluate_polynomial(coeffs: &[FieldElement], x: FieldElement) -> FieldElement {
    let mut acc = FieldElement::ZERO;
    for coeff in coeffs.iter().rev() {
        acc = acc.mul_mod(x).add_mod(*coeff);
    }
    acc
}

impl ConstantTimeEq for FieldElement {
    #[inline]
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    }
}

impl PartialEq for FieldElement {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for FieldElement {}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({} mod {})", self.value, FIELD_PRIME)
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Add for FieldElement {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        self.add_mod(rhs)
    }
}

impl Sub for FieldElement {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_mod(rhs)
    }
}

impl Neg for FieldElement {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        self.neg_mod()
    }
}

impl Mul for FieldElement {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_mod(rhs)
    }
}

impl Div for FieldElement {
    type Output = AegisResult<Self>;
    #[inline]
    fn div(self, rhs: Self) -> Self::Output {
        self.div_mod(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_range_enforcement() {
        assert!(FieldElement::from_canonical(0).is_ok());
        assert!(FieldElement::from_canonical(FIELD_PRIME - 1).is_ok());
        assert_eq!(
            FieldElement::from_canonical(FIELD_PRIME),
            Err(AegisError::FieldValueOutOfRange)
        );
        assert_eq!(
            FieldElement::from_canonical(u32::MAX),
            Err(AegisError::FieldValueOutOfRange)
        );
    }

    #[test]
    fn test_addition_and_subtraction_wrap_around() {
        let max_elem = FieldElement::from_canonical(FIELD_PRIME - 1).unwrap();
        let one = FieldElement::ONE;

        // (p - 1) + 1 === 0 (mod p)
        assert_eq!(max_elem + one, FieldElement::ZERO);

        // 0 - 1 === p - 1 (mod p)
        assert_eq!(FieldElement::ZERO - one, max_elem);

        // Additive inverse property: a + (-a) === 0 (mod p)
        let a = FieldElement::from_canonical(1_234_567_890).unwrap();
        assert_eq!(a + (-a), FieldElement::ZERO);
    }

    #[test]
    fn test_multiplication_does_not_overflow_at_boundary() {
        // (p - 1) * (p - 1) === (-1) * (-1) === 1 (mod p)
        let p_minus_1 = FieldElement::from_canonical(FIELD_PRIME - 1).unwrap();
        assert_eq!(p_minus_1 * p_minus_1, FieldElement::ONE);
    }

    #[test]
    fn test_fermat_little_theorem_and_multiplicative_inverse() {
        let values = [1u32, 2, 17, 65_535, 999_999_937, FIELD_PRIME - 1];

        for &v in &values {
            let a = FieldElement::from_canonical(v).unwrap();
            // Fermat's Little Theorem: a^(p - 1) === 1 (mod p)
            assert_eq!(a.pow_mod((FIELD_PRIME - 1) as u64), FieldElement::ONE);

            // Inverse property: a * a^(-1) === 1 (mod p)
            let inv = a.inverse().expect("non-zero element has inverse");
            assert_eq!(a * inv, FieldElement::ONE);
        }

        // Zero has no multiplicative inverse
        assert_eq!(
            FieldElement::ZERO.inverse(),
            Err(AegisError::DivisionByZero)
        );
    }

    #[test]
    fn test_field_axioms_distributivity_and_associativity() {
        let a = FieldElement::from_canonical(1_500_000_000).unwrap();
        let b = FieldElement::from_canonical(1_800_000_000).unwrap();
        let c = FieldElement::from_canonical(2_000_000_000).unwrap();

        // Distributivity: a * (b + c) == (a * b) + (a * c)
        assert_eq!(a * (b + c), (a * b) + (a * c));

        // Associativity of addition & multiplication
        assert_eq!((a + b) + c, a + (b + c));
        assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn test_polynomial_evaluation_horners_method() {
        // f(x) = 42 + 7x + 3x^2 (mod p)
        let c0 = FieldElement::from_canonical(42).unwrap();
        let c1 = FieldElement::from_canonical(7).unwrap();
        let c2 = FieldElement::from_canonical(3).unwrap();
        let coeffs = [c0, c1, c2];

        // At x = 0, f(0) must equal the constant secret term c0 = 42
        assert_eq!(evaluate_polynomial(&coeffs, FieldElement::ZERO), c0);

        // At x = 5, f(5) = 42 + 7(5) + 3(25) = 42 + 35 + 75 = 152
        let x5 = FieldElement::from_canonical(5).unwrap();
        let expected = FieldElement::from_canonical(152).unwrap();
        assert_eq!(evaluate_polynomial(&coeffs, x5), expected);
    }
}
