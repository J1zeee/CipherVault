using Xunit;

// AuditService is a process-wide singleton bound to the first log path it is given,
// so test classes must not race each other for it.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
