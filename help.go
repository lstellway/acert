package main

import (
	"flag"
	"fmt"
	"strings"
)

type CommandExample struct {
	description string
	example     string
}

type CommandSection struct {
	flags   []string
	flagSet *flag.FlagSet
	name    string
}

type CommandSubcommand struct {
	description string
	name        string
}

type Command struct {
	description string
	examples    []CommandExample
	flagSet     *flag.FlagSet
	name        string
	arguments   []string
	sections    []CommandSection
	subcommands []CommandSubcommand
}

// Add boolean
func (s *CommandSection) BoolVar(p *bool, name string, value bool, usage string) {
	s.flags = append(s.flags, name)
	s.flagSet.BoolVar(p, name, value, usage)
}

// Add integer
func (s *CommandSection) IntVar(p *int, name string, value int, usage string) {
	s.flags = append(s.flags, name)
	s.flagSet.IntVar(p, name, value, usage)
}

// Add a flag to a help seciton
func (s *CommandSection) StringVar(p *string, name string, value string, usage string) {
	s.flags = append(s.flags, name)
	s.flagSet.StringVar(p, name, value, usage)
}

// Add argument
func (h *Command) AddArgument(name string) {
	h.arguments = append(h.arguments, name)
}

// Add help section
func (h *Command) AddSection(name string, configure func(s *CommandSection)) {
	section := CommandSection{
		name:    name,
		flagSet: h.flagSet,
	}

	// Callback to configure section
	configure(&section)
	h.sections = append(h.sections, section)
}

// Add a subcommand
func (h *Command) AddSubcommand(name string, description string) {
	child := CommandSubcommand{
		name:        name,
		description: description,
	}
	h.subcommands = append(h.subcommands, child)
}

// Add example
func (h *Command) AddExample(description string, example string) {
	e := CommandExample{
		description: description,
		example:     example,
	}
	h.examples = append(h.examples, e)
}

// Usage
func (h *Command) Usage() {
	h.flagSet.Usage()
}

// Usage
func CommandUsage(h *Command) {
	var help strings.Builder

	// Description
	if len(h.description) > 0 {
		fmt.Fprintf(&help, "\n%s\n", h.description)
	}

	// Command name
	if len(h.flagSet.Name()) > 0 {
		var a strings.Builder
		for _, name := range h.arguments {
			fmt.Fprintf(&a, " [%s]", name)
		}

		fmt.Fprintf(&help, "\n\nUsage:\n")

		if len(h.sections) > 0 {
			fmt.Fprintf(&help, "\n    %s [OPTIONS]%s", h.flagSet.Name(), a.String())
		} else if len(h.subcommands) > 0 {
			fmt.Fprintf(&help, "\n    %s COMMAND%s", h.flagSet.Name(), a.String())
		} else {
			fmt.Fprintf(&help, "\n    %s%s", h.flagSet.Name(), a.String())
		}

		fmt.Fprintf(&help, "\n")
	}

	// Examples
	if len(h.examples) > 0 {
		fmt.Fprintf(&help, "\n\nExamples:\n")

		for _, e := range h.examples {
			if e.description != "" {
				fmt.Fprintf(&help, "\n    %s:", e.description)
			}
			fmt.Fprintf(&help, "\n      %s %s\n", h.flagSet.Name(), e.example)
		}
	}

	// Sections
	if len(h.sections) > 0 {
		for _, section := range h.sections {
			fmt.Fprintf(&help, "\n\n%s:\n", section.name)

			for _, name := range section.flags {
				// Get flag
				f := h.flagSet.Lookup(name)

				// Default value
				defValue := ""
				if f.DefValue != "" {
					defValue = fmt.Sprintf("; Default: %v", f.DefValue)
				}

				// Name, type, default
				fmt.Fprintf(&help, "\n   -%s", f.Name)
				fmt.Fprintf(&help, "\n    Type: %T%s\n", f.DefValue, defValue)

				// Usage
				_, flagUsage := flag.UnquoteUsage(f)
				flagUsage = strings.ReplaceAll(flagUsage, "\n", "\n    ")
				fmt.Fprintf(&help, "    %s\n", flagUsage)
			}
		}
	}

	// Subcommands
	if len(h.subcommands) > 0 {
		fmt.Fprintf(&help, "\n\nCommands:\n")

		for _, s := range h.subcommands {
			fmt.Fprintf(&help, "\n    %s", s.name)
			fmt.Fprintf(&help, "\n      %s\n", s.description)
		}

		fmt.Fprintf(&help, "\n\nRun '%s COMMAND' for more information on a command.\n", h.flagSet.Name())
	}

	fmt.Fprintf(h.flagSet.Output(), help.String())
}

// Build a new command helper
func NewCommand(name string, description string, configure func(h *Command), flags ...string) (Command, []string) {
	h := Command{
		name:        name,
		description: description,
		flagSet:     flag.NewFlagSet(name, flag.ExitOnError),
	}

	h.flagSet.Usage = func() {
		CommandUsage(&h)
	}
	configure(&h)

	h.flagSet.Parse(flags)
	return h, h.flagSet.Args()
}
