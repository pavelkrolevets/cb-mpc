package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ====================================================
// Existing types
// ====================================================

type SemiProcessedBenchmark struct {
	Category   string
	HeaderName string
	RowName    string
	ColName    string
	RawData    BenchmarkData
}

type AllBenchmarksData struct {
	Context    ContextData     `json:"context"`
	Benchmarks []BenchmarkData `json:"benchmarks"`
}

// ====================================================
// Main entry point
// ====================================================
func main() {
	args := os.Args
	showIndividualPages := true
	dataPath := "data"
	destinationPath := "../docs"
	if len(args) == 4 {
		showIndividualPages = args[1] == "true"
		dataPath = args[2]
		destinationPath = args[3]
	}

	fmt.Println(showIndividualPages, dataPath, destinationPath)

	var pageNames []string
	var err error
	if showIndividualPages {
		// Render each "individual page"
		pageNames, err = listDirectories(filepath.Join(dataPath, "individual_benchmarks"))
		if err != nil {
			panic(err)
		}
		if err := RenderOtherPages(pageNames, dataPath, destinationPath); err != nil {
			panic(err)
		}
	}

	// Render the main homepage
	if err := RenderHomepage(filepath.Join(dataPath, "aggregated_benchmarks.json"), pageNames, dataPath, destinationPath); err != nil {
		panic(err)
	}
}

// parseSource handles potential "Name+Name" summations
func parseSource(allBenches map[string]BenchmarkData, source string) (BenchmarkData, bool) {
	parts := strings.Split(source, "+")
	if len(parts) == 1 {
		bench, exists := allBenches[source]
		return bench, exists
	} else {
		// we want to sum the RealTimes
		var sum BenchmarkData
		var total float64
		for _, part := range parts {
			b, ex := allBenches[part]
			if !ex {
				return BenchmarkData{}, false
			}
			total += b.RealTime
			sum.TimeUnit = b.TimeUnit
		}
		sum.Name = "sum"
		sum.RealTime = total
		sum.Iterations = -1
		return sum, true
	}
}

// rowBenchToCell converts one BenchmarkData into a cell's displayed value + tooltip.
func rowBenchToCell(bench *BenchmarkData, cell *Cell) error {
	if bench == nil && cell.ValueType == "string" {
		// show .Source literally
		cell.Value = cell.Source
		return nil
	}

	// The user has e.g. "us" or "B" in cell.ValueType
	switch {
	case timeUnitDisplay[cell.ValueType] != "":
		valueNum, err := convertTime(bench.TimeUnit, cell.ValueType, bench.RealTime)
		if err != nil {
			return err
		}
		cell.Value = fmt.Sprintf("%.2f %s", valueNum, timeUnitDisplay[cell.ValueType])
		cell.Tooltip = bench.toTooltip()

	case spaceUnitDisplay[cell.ValueType] != "":
		valueNum, err := convertSpace(cell.ValueType, int64(bench.Size))
		if err != nil {
			return err
		}
		if cell.ValueType == "B" {
			cell.Value = fmt.Sprintf("%d %s", int(valueNum), spaceUnitDisplay[cell.ValueType])
		} else {
			cell.Value = fmt.Sprintf("%.2f %s", valueNum, spaceUnitDisplay[cell.ValueType])
		}

	case bidirSpaceUnitDisplay[cell.ValueType] != "":
		sendValueNum, err := convertSpace(cell.ValueType, int64(bench.SSize))
		if err != nil {
			return err
		}
		recvValueNum, err := convertSpace(cell.ValueType, int64(bench.RSize))
		if err != nil {
			return err
		}
		if cell.ValueType == "2B" {
			cell.Value = fmt.Sprintf("↑%d %s ↓%d %s", int(sendValueNum), bidirSpaceUnitDisplay[cell.ValueType], int(recvValueNum), bidirSpaceUnitDisplay[cell.ValueType])
		} else {
			cell.Value = fmt.Sprintf("↑%.2f %s ↓%.2f %s", sendValueNum, bidirSpaceUnitDisplay[cell.ValueType], recvValueNum, bidirSpaceUnitDisplay[cell.ValueType])
		}

	case cell.ValueType == "string":
		// Just display the source
		cell.Value = cell.Source

	default:
		return fmt.Errorf("unknown cell value type: %s", cell.ValueType)
	}
	return nil
}

// ====================================================
// Helper code
// ====================================================

// convertTime changes RealTime from the benchmark’s unit to the desired unit (ns/us/ms/s).
func convertTime(originalUnit string, targetUnit string, value float64) (float64, error) {
	if originalUnit == targetUnit {
		return value, nil
	}

	// Conversion factors to nanoseconds
	conversionFactors := map[string]float64{
		"ns": 1,
		"us": 1e3,
		"ms": 1e6,
		"s":  1e9,
	}

	// Check units
	origFactor, ok1 := conversionFactors[originalUnit]
	targFactor, ok2 := conversionFactors[targetUnit]
	if !ok1 || !ok2 {
		return 0, fmt.Errorf("invalid time unit (orig=%s, target=%s)", originalUnit, targetUnit)
	}

	// Convert
	converted := (value * origFactor) / targFactor
	return converted, nil
}

// convertSpace is similar but for Bytes/KB/MB/GB, including "sB" / "rB" style
func convertSpace(targetUnit string, value int64) (float64, error) {
	// If it starts with 's' or 'r', strip that off for the real unit
	if targetUnit[0] == '2' {
		targetUnit = targetUnit[1:]
	}
	if targetUnit == "B" {
		return float64(value), nil
	}

	conversionFactors := map[string]float64{
		"B":  1,
		"KB": 1e3,
		"MB": 1e6,
		"GB": 1e9,
	}

	targFactor, ok := conversionFactors[targetUnit]
	if !ok {
		return 0, fmt.Errorf("invalid space unit: %s", targetUnit)
	}
	return float64(value) / targFactor, nil
}
