use crate::metrics::http3_upstream::H3ResolverErrorClass;
use crate::upstream_resolution::ResolutionErrorClass;

pub(super) fn resolver_error_class(class: ResolutionErrorClass) -> H3ResolverErrorClass {
  match class {
    ResolutionErrorClass::Deadline => H3ResolverErrorClass::Timeout,
    ResolutionErrorClass::NxDomain => H3ResolverErrorClass::Nxdomain,
    ResolutionErrorClass::NoData => H3ResolverErrorClass::Nodata,
    ResolutionErrorClass::ServerFailure => H3ResolverErrorClass::Servfail,
    ResolutionErrorClass::Refused => H3ResolverErrorClass::Refused,
    ResolutionErrorClass::Malformed | ResolutionErrorClass::Truncated => {
      H3ResolverErrorClass::Malformed
    }
    ResolutionErrorClass::Io | ResolutionErrorClass::NoNameservers => H3ResolverErrorClass::Io,
    ResolutionErrorClass::Cancelled => H3ResolverErrorClass::Canceled,
    ResolutionErrorClass::InvalidInput | ResolutionErrorClass::Internal => {
      H3ResolverErrorClass::Other
    }
  }
}
