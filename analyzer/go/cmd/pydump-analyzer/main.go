package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/compforge/pydump/analyzer/go/internal/analysis"
	"github.com/compforge/pydump/analyzer/go/internal/heap"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pydump_analyzer failed: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "summary":
		return runSummary(args[1:])
	case "retained-heap":
		return runRetained(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runSummary(args []string) error {
	flags := flag.NewFlagSet("summary", flag.ContinueOnError)
	file := flags.String("file", "", "heap file name")
	flags.StringVar(file, "f", "", "heap file name")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *file == "" {
		return errors.New("summary requires --file")
	}
	return analyze(*file, false, 100, "json")
}

func runRetained(args []string) error {
	flags := flag.NewFlagSet("retained-heap", flag.ContinueOnError)
	file := flags.String("file", "", "heap file name")
	flags.StringVar(file, "f", "", "heap file name")
	topN := flags.Int("top-n", 100, "number of top objects to show")
	flags.IntVar(topN, "n", 100, "number of top objects to show")
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *file == "" {
		return errors.New("retained-heap requires --file")
	}
	if *topN < 0 {
		return errors.New("--top-n must be non-negative")
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unsupported format %q", *format)
	}
	return analyze(*file, true, *topN, *format)
}

func analyze(path string, calculateRetained bool, topN int, format string) error {
	value, err := heap.Load(path)
	if err != nil {
		return err
	}
	defer value.Close()
	var retained *analysis.RetainedHeap
	if calculateRetained {
		retained, err = analysis.RetainedHeapWithCache(path, value)
		if err != nil {
			return err
		}
	}
	report, err := analysis.BuildReport(path, value, retained, topN)
	if err != nil {
		return err
	}
	if format == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	printText(report)
	return nil
}

func printText(report *analysis.Report) {
	fmt.Println("Retained heap for objects:")
	fmt.Printf(
		"%-18s | %-24s | %18s | %s\n",
		"Address",
		"Object type",
		"Retained heap size",
		"String representation",
	)
	for _, object := range report.RetainedHeap.TopObjects {
		representation := ""
		if object.StringRepresentation != nil {
			representation = *object.StringRepresentation
		}
		fmt.Printf(
			"%-18s | %-24s | %18d | %s\n",
			object.ObjectAddress,
			object.TypeName,
			object.RetainedSizeBytes,
			representation,
		)
	}
	fmt.Println("\nRetained heap for threads:")
	threads := append([]analysis.ThreadSummary(nil), report.Threads...)
	sort.Slice(threads, func(i, j int) bool {
		return *threads[i].RetainedSizeBytes > *threads[j].RetainedSizeBytes
	})
	for _, thread := range threads {
		fmt.Printf("%-50s | %18d\n", thread.Name, *thread.RetainedSizeBytes)
	}
	fmt.Printf("\nTotal heap size: %d bytes\n", report.Heap.ShallowSizeBytes)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: pydump_analyzer {summary,retained-heap} [options]")
}
