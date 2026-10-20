package milter

// Resource outcomes are recorded at extraction boundaries.
type htmlProcessingUsage struct {
	primaryCPUExceeded     bool
	fallbackCPUExceeded    bool
	memoryExceeded         bool
	primaryMemoryExceeded  bool
	fallbackMemoryExceeded bool
	primaryMemoryBytes     int64
	fallbackMemoryBytes    int64
}

func (u htmlProcessingUsage) cpuExceeded() bool { return u.primaryCPUExceeded || u.fallbackCPUExceeded }
