#!/usr/bin/env ruby

class CalltypeBuilder
    
    def initialize(infile_name, outfile_name)
        @SYSCALL_REGEX = /asmlinkage\s+([\w ]+?)\s+(\w+)\((.+?)\);/
        @infile = File.new(infile_name, "r")
        @outfile = File.new(outfile_name, "w")
        @syscalls_processed = 0
        @maxargs = 0
    end

    def build_file
        @syscalls_processed = 0;
        syscall_def = ""
        param = ""
        skip_line = true;
    
        DATA.each_line do |data_line|

            if (data_line == "%s\n")
                @infile.each_line do |line|
                    line.strip!
                   
                    # Handle pre-processor directives
                    if (line[0,1] == "#")
                        if (! skip_line)
                            @outfile.print line << "\n"
                        end
                   
                    elsif (line == "")
                        skip_line = true

                    # All other lines
                    else
                        # Build statement
                        syscall_def << " " << line
                        syscall_def.strip!

                        if (syscall_def[-1,1] == ";")

                            # Matches a syscall definition
                            if (@SYSCALL_REGEX.match(syscall_def))
                                syscall_type_name = "#{$2}_t"
                                return_type = "#{$1}"

                                # Remove the parameter name
                                param = "#{$3}".split(/,/).map do |v|
                                    tokens = v.split(/\s+/)
                                    if (tokens[-1].gsub!(/(\w+)$/, "") == "")
                                        tokens.delete_at(-1)
                                    end
                                    tokens.join(" ")
                                end

                                if (param.length > @maxargs)
                                    @maxargs = param.length
                                end

                                param = param.join(",") 

                                @outfile.print "#define #{syscall_type_name} #{return_type} (*) (#{param})\n"
                                skip_line = false
                                @syscalls_processed += 1

                            # Doesn't match syscall definition
                            else
                                #print syscall_def << "\n"
                                skip_line = true
                            end

                            # Resent statement to empty
                            syscall_def  = ""
                        end
                    end
                end
            else
                @outfile.print data_line
            end
        end
    end

    def finalize
        print "#{@syscalls_processed} system calls processed.\n"
        print "Maximum number of arguments for calls: #{@maxargs}\n"
        print "Finished.\n\n"
        @infile.close
        @outfile.close
    end
end

if (ARGV.size == 2)
    builder = CalltypeBuilder.new(ARGV[0], ARGV[1])
    builder.build_file
    builder.finalize
else
    print "Builds type definitions for function pointers to system calls in the Linux kernel.\n\n"
    print "Usage: ./build_type_defs.rb <syscalls.h_location> <output_file_name>\n";
end

__END__
#ifndef _SYSCALL_TYPES_H
#define _SYSCALL_TYPES_H

%s

#endif
